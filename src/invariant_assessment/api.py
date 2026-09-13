"""Thin FastAPI wrapper over invariant_assessment's own evaluation engine
(CHECKS/document_slug_for_os) -- exposes exactly the shape invariant_api's
routes/assess.py needs, and nothing else. No Postgres here, ever: this
service only knows "which check titles passed/failed, with what
evidence" -- turning that into a real Finding (external_id, remediation,
CIS level/scored) is invariant_api's job, which owns the database.
"""

from fastapi import FastAPI, HTTPException, Response
from pydantic import BaseModel, Field

from invariant_assessment import CHECKS, document_slug_for_os, family_for_os
from invariant_assessment.facts import collect_facts
from invariant_assessment.observability import timed
from invariant_assessment.transport import (
    DockerExecTransport,
    SSHTransport,
    TransportAuthError,
    TransportTimeoutError,
    TransportUnreachableError,
    list_docker_containers,
)

app = FastAPI(title="Invariant Assessment")


@app.get("/healthz")
def healthz() -> dict:
    return {"status": "ok"}


class ContainerInfo(BaseModel):
    name: str
    image: str


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
    titles: list[str]
    status: str
    evidence: str


class RunResponse(BaseModel):
    document: str
    results: list[CheckResult]


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


def _evaluate_all(facts, target_label: str) -> RunResponse:
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
            titles=check.titles,
            status="PASS" if check.evaluate(facts) else "FAIL",
            evidence=check.evidence(facts),
        )
        for check in applicable_checks
    ]
    return RunResponse(document=document, results=results)


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
    reason_code: str | None = None  # "os_not_detected" | "unsupported_os"
    reason: str | None = None  # human-readable, never a raw str(exception)


@app.post("/assessment/check", response_model=CheckResponse)
def check_target(target: str, response: Response) -> CheckResponse:
    # Cache-Control: no-store -- this is about the container's *current*
    # state, and a container can be recreated (same name, different OS)
    # between calls; GET-like semantics on the public route this backs
    # (invariant_api's GET /containers/{name}/check) must not be cached.
    response.headers["Cache-Control"] = "no-store"
    facts = collect_facts(DockerExecTransport(target=target))
    if not facts.os_id or not facts.os_version_id:
        return CheckResponse(
            testable=False,
            reason_code="os_not_detected",
            reason="Could not detect the operating system for this container.",
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
        )
    return CheckResponse(testable=True, os_id=facts.os_id, os_version_id=facts.os_version_id, family=family)


@app.post("/assessment/run", response_model=RunResponse)
def run_assessment(target: str) -> RunResponse:
    """One `docker exec` (collect_facts) against `target`, then every
    CHECKS entry evaluated against that single snapshot. `target` is a
    query param (not a body) since it's the only input -- matches how
    lightweight this call is meant to stay.
    """
    transport = DockerExecTransport(target=target)
    with timed(f"collect_facts:{target}"):
        facts = collect_facts(transport)
    return _evaluate_all(facts, target)


@app.post("/assessment/run-remote", response_model=RunResponse)
def run_assessment_remote(payload: SSHRemoteTarget) -> RunResponse:
    """Same pipeline as /assessment/run, reached over SSH instead of
    docker exec. The timed() label below deliberately includes only
    username@host:port -- NEVER auth_method/key_material/password.
    """
    transport = SSHTransport(
        host=payload.host,
        port=payload.port,
        username=payload.username,
        auth_method=payload.auth_method,
        key_material=payload.key_material,
        password=payload.password,
    )
    label = f"collect_facts:ssh:{payload.username}@{payload.host}:{payload.port}"
    try:
        with timed(label):
            facts = collect_facts(transport)
    except TransportAuthError as e:
        raise HTTPException(401, str(e)) from e
    except TransportUnreachableError as e:
        raise HTTPException(502, str(e)) from e
    except TransportTimeoutError as e:
        raise HTTPException(504, str(e)) from e
    return _evaluate_all(facts, payload.host)
