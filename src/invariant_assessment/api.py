"""Thin FastAPI wrapper over invariant_assessment's own evaluation engine
(CHECKS/document_slug_for_os) -- exposes exactly the shape invariant_api's
routes/assess.py needs, and nothing else. No Postgres here, ever: this
service only knows "which check ids passed/failed, with what
evidence" -- turning that into a real Finding (external_id, remediation,
level, scored flag) is invariant_api's job, which owns the database.
"""

from typing import Literal

from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, model_validator

from invariant_assessment import CHECKS, document_slug_for_os, family_for_os, internal_auth
from invariant_assessment.facts import clean_hostname, collect_facts
from invariant_assessment.observability import timed
from invariant_assessment.transport import (
    DockerExecTransport,
    HostKeyMismatch,
    SSHTransport,
    TransportAuthError,
    TransportTimeoutError,
    TransportUnreachableError,
    list_docker_containers,
)

app = FastAPI(title="Invariant Assessment")
internal_auth.install(app)


@app.exception_handler(RequestValidationError)
def _validation_error(request: Request, exc: RequestValidationError) -> JSONResponse:
    """FastAPI's default 422 echoes `input` (and `ctx`), which for the
    run-remote/check-remote bodies is the SSH password or private key. Only
    loc/msg/type leave this service.
    """
    return JSONResponse(
        status_code=422,
        content={"detail": [{"loc": list(e["loc"]), "msg": e["msg"], "type": e["type"]} for e in exc.errors()]},
    )


@app.get("/healthz")
def healthz() -> dict:
    return {"status": "ok"}


class ContainerInfo(BaseModel):
    name: str
    image: str
    id: str
    is_demo: bool = False


@app.get("/assessment/containers", response_model=list[ContainerInfo])
def containers() -> list[ContainerInfo]:
    """Candidates for /assessment/run's `target` -- every container this
    host's Docker socket can see. Filtering out invariant's own stack
    (appliance/demo/infra, not a client asset) is invariant_api's job,
    since it's the one with an opinion about naming conventions across
    deployments; this stays a plain, unfiltered `docker ps`.
    """
    return [ContainerInfo(**c) for c in list_docker_containers()]


class CheckResult(BaseModel):
    check_id: str
    status: str
    evidence: str


class HostKeyObserved(BaseModel):
    type: str
    fingerprint: str


class RunResponse(BaseModel):
    document: str
    results: list[CheckResult]
    # SSH only. "operator" = matched the pin; "first_use" = accepted without a pin.
    host_key_observed: HostKeyObserved | None = None
    host_key_verification: Literal["operator", "first_use"] | None = None


class SSHRemoteTarget(BaseModel):
    """Body for POST /assessment/run-remote. Credentials are used exactly
    once to build this request's SSHTransport, then discarded when the
    function returns -- never logged, never stored, never echoed back in
    RunResponse.
    """

    host: str
    port: int = 22
    username: str
    auth_method: str  # "key" | "password"
    key_material: str | None = Field(default=None, repr=False)
    password: str | None = Field(default=None, repr=False)
    # Same names/values as invariant_contracts v1 SSHCredentials (v0.4.0);
    # copied, not imported, on purpose (see pyproject.toml).
    host_key_type: Literal[
        "ssh-ed25519", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521", "ssh-rsa"
    ] | None = None
    host_key_fingerprint: str | None = Field(default=None, pattern=r"^SHA256:[A-Za-z0-9+/]{43}$")
    host_key_mode: Literal["pinned", "first_use"] | None = None

    @model_validator(mode="after")
    def _host_key_rules(self) -> "SSHRemoteTarget":
        if (self.host_key_type is None) != (self.host_key_fingerprint is None):
            raise ValueError("host_key_type e host_key_fingerprint andam juntos")
        if self.host_key_mode == "pinned" and self.host_key_fingerprint is None:
            raise ValueError("host_key_mode=pinned exige host_key_type e host_key_fingerprint")
        if self.host_key_mode == "first_use" and self.host_key_fingerprint is not None:
            raise ValueError("host_key_mode=first_use não aceita host_key_fingerprint")
        if self.auth_method == "password" and self.host_key_fingerprint is None:
            raise ValueError("auth_method=password exige host_key_fingerprint (senha nunca vai com first_use)")
        return self

    def transport(self) -> SSHTransport:
        # No pin (old payload, or first_use) = TOFU.
        return SSHTransport(
            host=self.host,
            port=self.port,
            username=self.username,
            auth_method=self.auth_method,
            key_material=self.key_material,
            password=self.password,
            host_key_type=self.host_key_type,
            host_key_fingerprint=self.host_key_fingerprint,
        )


def _host_key_fields(transport: SSHTransport) -> dict:
    observed = transport.host_key_observed
    return {
        "host_key_observed": observed,
        "host_key_verification": ("operator" if transport.host_key_fingerprint else "first_use") if observed else None,
    }


def _mismatch(e: HostKeyMismatch) -> HTTPException:
    """409 + detail.code=host_key_mismatch; only what the server presented."""
    return HTTPException(
        409,
        {
            "code": "host_key_mismatch",
            "host_key_observed": {"type": e.key_type, "fingerprint": e.fingerprint},
        },
    )


def _evaluate_all(facts, target_label: str, extra: dict | None = None) -> RunResponse:
    if not facts.os_id or not facts.os_version_id:
        raise HTTPException(422, f"could not detect OS for {target_label!r}")
    document = document_slug_for_os(facts.os_id, facts.os_version_id)

    try:
        family = family_for_os(facts.os_id, facts.os_version_id)
    except LookupError as e:
        raise HTTPException(422, str(e)) from e

    applicable_checks = [check for check in CHECKS if check.family == family]

    results = [
        CheckResult(
            check_id=check.id,
            status="PASS" if check.evaluate(facts) else "FAIL",
            evidence=check.evidence(facts),
        )
        for check in applicable_checks
    ]
    return RunResponse(document=document, results=results, **(extra or {}))


class CheckResponse(BaseModel):
    """Cheap pre-flight for /assessment/run's `target` -- detects OS and
    checks it against the same family_for_os() gate _evaluate_all() uses,
    but stops there (no CHECKS loop). Lets a caller ask "can this even be
    assessed" before committing to a real run. `testable` has no default
    on purpose: every return path below must set it explicitly, so a
    missing branch fails loudly (Pydantic validation error) instead of
    silently defaulting to a value that happens to be wrong.
    """

    testable: bool
    os_id: str | None = None
    os_version_id: str | None = None
    family: str | None = None
    reason_code: str | None = None  # "collection_failed" | "os_not_detected" | "unsupported_os"
    reason: str | None = None  # human-readable, never a raw str(exception)
    hostname: str | None = None  # None if collection failed or the result didn't look like a real hostname
    host_key_observed: HostKeyObserved | None = None  # SSH only, see RunResponse
    host_key_verification: Literal["operator", "first_use"] | None = None


@app.post("/assessment/check", response_model=CheckResponse)
def check_target(target: str, response: Response) -> CheckResponse:
    # Cache-Control: no-store -- this is about the container's *current*
    # state, and a container can be recreated (same name, different OS)
    # between calls; GET-like semantics on the public route this backs
    # (invariant_api's GET /containers/{name}/check) must not be cached.
    response.headers["Cache-Control"] = "no-store"
    try:
        facts = collect_facts(DockerExecTransport(target=target))
    except LookupError:
        # collect_facts() raises a plain LookupError when the collection
        # script didn't run as expected -- found live against a real
        # container (loki, a distroless-style image with no `sh` at all:
        # "docker exec ... sh -c ..." fails at the OCI runtime level
        # before any of our script ever runs). Same thing could mean the
        # container stopped between listing and checking it. Either way,
        # this is "can't tell you anything about this container", not a
        # server error.
        return CheckResponse(
            testable=False,
            reason_code="collection_failed",
            reason="Could not collect information from this container (no shell, or it may not be running).",
        )
    hostname = clean_hostname(facts.hostname_probe_raw)
    if not facts.os_id or not facts.os_version_id:
        return CheckResponse(
            testable=False,
            reason_code="os_not_detected",
            reason="Could not detect the operating system for this container.",
            hostname=hostname,
        )
    try:
        family = family_for_os(facts.os_id, facts.os_version_id)
    except LookupError:
        return CheckResponse(
            testable=False,
            os_id=facts.os_id,
            os_version_id=facts.os_version_id,
            reason_code="unsupported_os",
            reason=f"{facts.os_id} {facts.os_version_id} is not supported yet.",
            hostname=hostname,
        )
    return CheckResponse(
        testable=True, os_id=facts.os_id, os_version_id=facts.os_version_id, family=family, hostname=hostname
    )


@app.post("/assessment/run", response_model=RunResponse)
def run_assessment(target: str) -> RunResponse:
    """One `docker exec` (collect_facts) against `target`, then every
    CHECKS entry evaluated against that single snapshot. `target` is a
    query param (not a body) since it's the only input -- matches how
    lightweight this call is meant to stay.
    """
    transport = DockerExecTransport(target=target)
    try:
        with timed(f"collect_facts:{target}"):
            facts = collect_facts(transport)
    except LookupError as e:
        # Same collection-failure mode /assessment/check now handles
        # gracefully (e.g. a container with no shell at all) -- found live
        # against loki. A 422 here, not an unhandled 500.
        raise HTTPException(422, str(e)) from e
    return _evaluate_all(facts, target)


@app.post("/assessment/run-remote", response_model=RunResponse)
def run_assessment_remote(payload: SSHRemoteTarget) -> RunResponse:
    """Same pipeline as /assessment/run, reached over SSH instead of
    docker exec. The timed() label below deliberately includes only
    username@host:port -- NEVER auth_method/key_material/password.
    """
    transport = payload.transport()
    label = f"collect_facts:ssh:{payload.username}@{payload.host}:{payload.port}"
    try:
        with timed(label):
            facts = collect_facts(transport)
    except HostKeyMismatch as e:
        raise _mismatch(e) from e
    except TransportAuthError as e:
        raise HTTPException(401, str(e)) from e
    except TransportUnreachableError as e:
        raise HTTPException(502, str(e)) from e
    except TransportTimeoutError as e:
        raise HTTPException(504, str(e)) from e
    return _evaluate_all(facts, payload.host, _host_key_fields(transport))


@app.post("/assessment/check-remote", response_model=CheckResponse)
def check_remote(payload: SSHRemoteTarget, response: Response) -> CheckResponse:
    """SSH twin of /assessment/check -- same cheap pre-flight (OS
    detection, family_for_os() gate, no CHECKS loop), reached over SSH
    instead of docker exec. Auth/network failures are real errors here
    (401/502/504, same mapping /assessment/run-remote already uses), not
    a soft testable=False -- unlike collection succeeding but finding no
    shell/OS, which (like the docker-exec path) just means "can't tell
    you anything about this host".
    """
    response.headers["Cache-Control"] = "no-store"
    transport = payload.transport()
    try:
        facts = collect_facts(transport)
    except LookupError:
        return CheckResponse(
            testable=False,
            reason_code="collection_failed",
            reason="Could not collect information from this host (check connectivity).",
            **_host_key_fields(transport),
        )
    except HostKeyMismatch as e:
        raise _mismatch(e) from e
    except TransportAuthError as e:
        raise HTTPException(401, str(e)) from e
    except TransportUnreachableError as e:
        raise HTTPException(502, str(e)) from e
    except TransportTimeoutError as e:
        raise HTTPException(504, str(e)) from e
    hostname = clean_hostname(facts.hostname_probe_raw)
    if not facts.os_id or not facts.os_version_id:
        return CheckResponse(
            testable=False,
            reason_code="os_not_detected",
            reason="Could not detect the operating system for this host.",
            hostname=hostname,
            **_host_key_fields(transport),
        )
    try:
        family = family_for_os(facts.os_id, facts.os_version_id)
    except LookupError:
        return CheckResponse(
            testable=False,
            os_id=facts.os_id,
            os_version_id=facts.os_version_id,
            reason_code="unsupported_os",
            reason=f"{facts.os_id} {facts.os_version_id} is not supported yet.",
            hostname=hostname,
            **_host_key_fields(transport),
        )
    return CheckResponse(
        testable=True, os_id=facts.os_id, os_version_id=facts.os_version_id, family=family, hostname=hostname,
        **_host_key_fields(transport),
    )
