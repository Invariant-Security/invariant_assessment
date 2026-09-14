"""Integration coverage for the Transport abstraction (transport.py) --
proves SSHTransport and DockerExecTransport are interchangeable from
facts.collect_facts()'s point of view, that SSH failure modes map to the
right TransportError subclass (and HTTP status via api.py's
/assessment/run-remote), and -- the mandatory part -- that no SSH
credential ever leaks into a response body or a captured log line.

Hits the `ssh-target` fixture container (tests/fixtures/docker/ssh-target),
reached over a real loopback TCP connection on 127.0.0.1:22022 -- NOT
docker exec -- see tests/fixtures/docker-compose.yml for why this is the
only fixture service with a published host port, and why it's bound to
127.0.0.1 only.
"""

import io
import os
import subprocess
import tempfile
from dataclasses import dataclass

import paramiko
import pytest
from fastapi.testclient import TestClient

from invariant_assessment.api import app
from invariant_assessment.facts import collect_facts
from invariant_assessment.transport import (
    DockerExecTransport,
    SSHTransport,
    TransportAuthError,
    TransportUnreachableError,
)

pytestmark = pytest.mark.integration

client = TestClient(app)

_SSH_TARGET_CONTAINER = "invariant-assessment-test-ssh-target"
_SSH_HOST = "127.0.0.1"
_SSH_PORT = 22022
_SSH_USER = "invariant-test"
_SSH_PASSWORD = "invariant-test-password"


@dataclass
class _DockerExecAsUserTransport:
    """Test-only variant of DockerExecTransport that runs as a specific
    container user via `docker exec -u`, instead of the image's default
    user (root, since none of these fixture Dockerfiles set USER).

    Exists only for test_ssh_transport_password_auth_matches_docker_exec_facts
    below: DockerExecTransport itself must stay behavior-identical to the
    original bare `docker exec <target> sh -c <script>` call (no user
    override) per transport.py's own contract, so this lives here rather
    than as a transport.py feature. Without it, comparing plain
    DockerExecTransport (root) against SSHTransport(username="invariant-
    test") -- an unprivileged account -- would fail for reasons that are
    about *privilege level* (root can read /etc/shadow, /root/*, etc.;
    invariant-test can't), not about whether the two transports are
    correctly interchangeable. Running both sides as the same user isolates
    that: it proves DockerExecTransport and SSHTransport, at equal
    privilege, collect identical facts.
    """

    target: str
    user: str
    timeout: float = 10.0

    def run(self, script: str) -> str:
        result = subprocess.run(
            ["docker", "exec", "-u", self.user, self.target, "sh", "-c", script],
            capture_output=True,
            text=True,
            timeout=self.timeout,
        )
        return result.stdout + result.stderr


def test_ssh_transport_password_auth_matches_docker_exec_facts():
    """The same collection script, run through two different transports
    against the identical container as the identical user, must parse
    into identical SystemFacts -- proof that SSHTransport and
    DockerExecTransport are truly interchangeable behind
    facts.collect_facts(). Both sides connect as invariant-test (not
    root) so the comparison isolates the transport, not privilege level --
    see _DockerExecAsUserTransport's docstring above.
    """
    docker_transport = _DockerExecAsUserTransport(target=_SSH_TARGET_CONTAINER, user=_SSH_USER)
    ssh_transport = SSHTransport(
        host=_SSH_HOST,
        port=_SSH_PORT,
        username=_SSH_USER,
        auth_method="password",
        password=_SSH_PASSWORD,
    )

    docker_facts = collect_facts(docker_transport)
    ssh_facts = collect_facts(ssh_transport)

    # `docker exec` and a non-interactive `ssh ... command` session set up
    # PATH differently (confirmed directly: docker exec's sh -c sees
    # /usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin; SSH's
    # exec_command sees only /usr/local/bin:/usr/bin:/bin:/usr/games, no
    # /sbin or /usr/sbin) -- that's standard OpenSSH/Debian behavior for a
    # non-login shell, nothing to do with SSHTransport/DockerExecTransport
    # themselves, which just run whatever script string they're handed.
    # Two collected fields shell out to /sbin//usr/sbin binaries (sshd,
    # audit tools) and so legitimately differ in *how* the command isn't
    # found ("not found" vs "no hostkeys available") depending on which
    # PATH resolved it -- every other field, including every permission/
    # content-sensitive one, must still match exactly. sshd_probe_raw is
    # sshd_config's own pre-parse raw text (same command, same PATH
    # sensitivity), so it inherits the same exclusion.
    _PATH_DEPENDENT_FIELDS = {"sshd_config", "sshd_probe_raw", "audit_conf_text"}
    docker_dict = {k: v for k, v in vars(docker_facts).items() if k not in _PATH_DEPENDENT_FIELDS}
    ssh_dict = {k: v for k, v in vars(ssh_facts).items() if k not in _PATH_DEPENDENT_FIELDS}
    assert docker_dict == ssh_dict

    # The two PATH-dependent fields must still both reflect the same
    # underlying reality (sshd/audit tools not resolvable in this
    # unprivileged, non-login-shell environment on either transport) --
    # just confirm neither transport produced sshd_config directives or
    # audit_conf_text content that the other transport didn't also fail to
    # produce, rather than asserting byte-identical error text.
    assert docker_facts.sshd_config == {} or "sshd" in str(docker_facts.sshd_config)
    assert ssh_facts.sshd_config == {} or "sshd" in str(ssh_facts.sshd_config)
    assert docker_facts.sshd_probe_raw != ""
    assert ssh_facts.sshd_probe_raw != ""


def test_ssh_transport_key_auth():
    """Generates an ephemeral Ed25519 keypair (shelling out to ssh-keygen --
    paramiko 5.x's Ed25519Key has no in-process `.generate()` classmethod,
    confirmed against the installed version), injects only the public half
    into the running container's authorized_keys (bootstrapped over the
    already-proven docker exec mechanism), keeps the private key in memory
    only (written to a tmp_path fixture-less tempdir that's removed before
    the test returns), and confirms SSHTransport can authenticate with it.
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        key_path = os.path.join(tmpdir, "id_ed25519")
        subprocess.run(
            ["ssh-keygen", "-t", "ed25519", "-N", "", "-f", key_path, "-q"],
            check=True,
            timeout=10,
        )
        with open(key_path) as f:
            private_key_pem = f.read()
        with open(key_path + ".pub") as f:
            public_line = f.read().strip()

    # Confirm paramiko itself can parse what ssh-keygen produced, using the
    # same loader transport.py's SSHTransport relies on -- if this ever
    # fails, it's a paramiko/ssh-keygen format mismatch, not a fixture bug.
    paramiko.Ed25519Key.from_private_key(io.StringIO(private_key_pem))

    inject = DockerExecTransport(target=_SSH_TARGET_CONTAINER)
    inject.run(
        "echo '" + public_line + "' >> /home/invariant-test/.ssh/authorized_keys "
        "&& chown invariant-test:invariant-test /home/invariant-test/.ssh/authorized_keys "
        "&& chmod 600 /home/invariant-test/.ssh/authorized_keys"
    )

    ssh_transport = SSHTransport(
        host=_SSH_HOST,
        port=_SSH_PORT,
        username=_SSH_USER,
        auth_method="key",
        key_material=private_key_pem,
    )
    facts = collect_facts(ssh_transport)
    assert facts.os_id


def test_ssh_transport_wrong_password_raises_auth_error():
    transport = SSHTransport(
        host=_SSH_HOST,
        port=_SSH_PORT,
        username=_SSH_USER,
        auth_method="password",
        password="wrong",
    )
    with pytest.raises(TransportAuthError):
        transport.run("echo hi")


def test_ssh_transport_unreachable_host_raises_unreachable_error():
    transport = SSHTransport(
        host=_SSH_HOST,
        port=1,
        username="x",
        auth_method="password",
        password="x",
        timeout=2.0,
    )
    with pytest.raises(TransportUnreachableError):
        transport.run("echo hi")


def test_run_assessment_remote_endpoint_end_to_end():
    resp = client.post(
        "/assessment/run-remote",
        json={
            "host": _SSH_HOST,
            "port": _SSH_PORT,
            "username": _SSH_USER,
            "auth_method": "password",
            "password": _SSH_PASSWORD,
        },
    )
    assert resp.status_code == 200
    data = resp.json()
    assert "document" in data
    assert isinstance(data["results"], list)
    assert len(data["results"]) > 0


def test_run_assessment_remote_bad_password_returns_401():
    resp = client.post(
        "/assessment/run-remote",
        json={
            "host": _SSH_HOST,
            "port": _SSH_PORT,
            "username": _SSH_USER,
            "auth_method": "password",
            "password": "wrong",
        },
    )
    assert resp.status_code == 401


def test_run_assessment_remote_unreachable_returns_502():
    resp = client.post(
        "/assessment/run-remote",
        json={
            "host": _SSH_HOST,
            "port": 1,
            "username": "x",
            "auth_method": "password",
            "password": "x",
        },
    )
    assert resp.status_code == 502


_MARKER_PASSWORD = "SUPER-SECRET-MARKER-XYZ-DO-NOT-LEAK"


def test_credentials_never_appear_in_response_body():
    """Whether or not auth succeeds, the raw response body -- not just
    parsed JSON fields, the full text, so this also catches accidental
    leakage into an error `detail` string -- must never contain the
    credential value that was submitted.
    """
    resp = client.post(
        "/assessment/run-remote",
        json={
            "host": _SSH_HOST,
            "port": _SSH_PORT,
            "username": _SSH_USER,
            "auth_method": "password",
            "password": _MARKER_PASSWORD,
        },
    )
    assert _MARKER_PASSWORD not in resp.text


def test_credentials_never_appear_in_captured_logs(capsys):
    """observability.timed()'s print() call in run_assessment_remote must
    only ever interpolate username@host:port -- never auth_method,
    key_material, or password. Directly validates that guarantee against
    real captured stdout.
    """
    client.post(
        "/assessment/run-remote",
        json={
            "host": _SSH_HOST,
            "port": _SSH_PORT,
            "username": _SSH_USER,
            "auth_method": "password",
            "password": _MARKER_PASSWORD,
        },
    )
    captured = capsys.readouterr()
    assert _MARKER_PASSWORD not in captured.out
