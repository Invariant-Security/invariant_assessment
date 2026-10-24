"""Pluggable "how do we reach a target" layer. facts.collect_facts() talks
to exactly one Transport per call -- it never knows if that means `docker
exec` or SSH. Every Transport implementation must uphold the same
contract: one round trip, capture combined stdout+stderr as text, same
~10s budget as the original docker-exec-only collect_facts().
"""

import base64
import hashlib
import hmac
from dataclasses import dataclass, field
from typing import Protocol

import paramiko


class Transport(Protocol):
    def run(self, script: str) -> str:
        """Runs `script` (a shell command string) against the target and
        returns combined stdout+stderr as text. Must raise TransportError
        (or a subclass) on any failure that means "we didn't get a usable
        script result" -- unreachable host, auth failure, timeout. A
        script whose *individual* commands fail internally (e.g. `cat`
        against a missing file) is NOT a Transport-level error -- that
        error text just becomes part of the returned string.
        """
        ...


class TransportError(Exception):
    """Base class for all transport-level failures."""


class TransportUnreachableError(TransportError):
    """Could not establish a connection to the target at all."""


class TransportAuthError(TransportError):
    """Connection reached the target but authentication failed."""


class HostKeyMismatch(TransportError):
    """The server's host key is not the one pinned by the operator. Carries
    only what the server presented (`None` when it offered no key of the
    pinned type at all) -- never any credential.
    """

    def __init__(self, key_type: str | None, fingerprint: str | None) -> None:
        super().__init__(f"host key mismatch (seen {key_type} {fingerprint})")
        self.key_type = key_type
        self.fingerprint = fingerprint


class TransportTimeoutError(TransportError):
    """Connected (and authenticated, if applicable) but the script did
    not finish within the transport's timeout.
    """


@dataclass
class DockerExecTransport:
    """Wraps the exact `docker exec <target> sh -c <script>` call that
    collect_facts() used to make directly -- behavior-identical, just
    relocated behind the Transport protocol. `target` is the Docker
    container name.
    """

    target: str
    timeout: float = 10.0

    def run(self, script: str) -> str:
        import subprocess

        try:
            result = subprocess.run(
                ["docker", "exec", self.target, "sh", "-c", script],
                capture_output=True,
                text=True,
                timeout=self.timeout,
            )
        except subprocess.TimeoutExpired as e:
            raise TransportTimeoutError(
                f"docker exec against {self.target!r} timed out after {self.timeout}s"
            ) from e
        except FileNotFoundError as e:
            raise TransportUnreachableError("docker binary not found") from e
        return result.stdout + result.stderr


def list_docker_containers() -> list[dict]:
    """Names+images+IDs+demo-label of every running container reachable
    by this host's Docker socket -- what DockerExecTransport's `target`
    can point at. Same `docker` CLI dependency as DockerExecTransport.run(),
    no Docker SDK needed for a one-shot `docker ps`.

    `--no-trunc` is required: without it Docker truncates `{{.ID}}` to
    12 characters, which invariant_api's demo-snapshot alias table uses
    as a stable primary key (a rename/restart of the same container
    must keep the same ID -- a truncated ID has a real, if small,
    collision risk across the fleet).

    `{{.Label "invariant.public-demo"}}` -- confirmed live against a
    real Docker daemon that this reads inline from `docker ps` with no
    extra `docker inspect` round-trip: unlabeled containers produce an
    empty 4th field, `--label invariant.public-demo=true` produces
    `"true"`. This is the ONLY thing that marks a container eligible
    for the public demo snapshot (invariant_api's routes/demo_snapshot.py)
    -- never inferred from name.
    """
    import subprocess

    result = subprocess.run(
        ["docker", "ps", "--no-trunc", "--format", '{{.Names}}|{{.Image}}|{{.ID}}|{{.Label "invariant.public-demo"}}'],
        capture_output=True,
        text=True,
        timeout=10,
    )
    containers = []
    for line in result.stdout.strip().splitlines():
        if not line:
            continue
        name, _, rest = line.partition("|")
        image, _, rest = rest.partition("|")
        container_id, _, is_demo_label = rest.partition("|")
        containers.append({"name": name, "image": image, "id": container_id, "is_demo": is_demo_label == "true"})
    return containers


def _load_private_key(key_material: str):
    """Tries each paramiko key type in turn (Ed25519 first -- most common
    for real-world fleets today -- then ECDSA, RSA, DSS) since paramiko
    has no single "detect and load any key type" helper across older
    versions. Raises TransportAuthError if none parse.

    DSSKey (DSA) was removed from paramiko in the 4.x/5.x series (deprecated
    algorithm) -- `getattr` here so this still works against whichever of
    the four classes the installed paramiko version actually provides,
    instead of raising AttributeError before we even get to try a key.
    """
    import io

    import paramiko

    key_class_names = ["Ed25519Key", "ECDSAKey", "RSAKey", "DSSKey"]
    key_classes = [cls for name in key_class_names if (cls := getattr(paramiko, name, None)) is not None]
    last_error = None
    for key_class in key_classes:
        try:
            return key_class.from_private_key(io.StringIO(key_material))
        except paramiko.SSHException as e:
            last_error = e
            continue
    raise TransportAuthError(f"could not parse private key material as any known key type: {last_error}")


def host_key_fingerprint(key: "paramiko.PKey") -> str:
    """OpenSSH format: "SHA256:" + base64(sha256(public blob)) without padding."""
    return "SHA256:" + base64.b64encode(hashlib.sha256(key.asbytes()).digest()).decode().rstrip("=")


# Every host key algorithm paramiko can negotiate (+ ssh-rsa, the key-type
# name of an RSA key). A pinned connection disables all but the pinned
# type's, so the server cannot dodge the pin by offering another type.
# RSA host keys are signed as rsa-sha2-*; all three names stay enabled for
# an rsa pin (current paramiko only offers the sha2 ones).
_HOST_KEY_ALGS = (
    "ssh-ed25519",
    "ecdsa-sha2-nistp256",
    "ecdsa-sha2-nistp384",
    "ecdsa-sha2-nistp521",
    "rsa-sha2-512",
    "rsa-sha2-256",
    "ssh-rsa",
)
_RSA_ALGS = {"ssh-rsa", "rsa-sha2-512", "rsa-sha2-256"}


class _HostKeyPolicy(paramiko.MissingHostKeyPolicy):
    """Runs inside SSHClient.connect() right after the key exchange and
    BEFORE any authentication, so a rejected key means no password and no
    private-key signature ever left this process.
    """

    def __init__(self, pinned_fingerprint: str | None) -> None:
        self.pinned_fingerprint = pinned_fingerprint
        self.observed: dict | None = None

    def missing_host_key(self, client, hostname, key) -> None:
        fp = host_key_fingerprint(key)
        self.observed = {"type": key.get_name(), "fingerprint": fp}
        if self.pinned_fingerprint is not None and not hmac.compare_digest(
            fp.encode(), self.pinned_fingerprint.encode()
        ):
            raise HostKeyMismatch(key.get_name(), fp)


@dataclass
class SSHTransport:
    """Runs the script over a real SSH connection via paramiko. Ephemeral
    per call -- opens a connection, runs one command, closes, never
    caches or persists the client or any credential material.

    auth_method is "key" or "password"; exactly one of key_material/
    password must be set to match it.

    SECURITY: key_material and password use field(repr=False) below --
    do not remove this. Without it, dataclass auto-generates a __repr__
    that would print the secret in plaintext on any accidental
    print(transport) / log of this object. This is the single most
    important guard in this file.
    """

    host: str
    port: int
    username: str
    auth_method: str  # "key" | "password"
    key_material: str | None = field(default=None, repr=False)
    password: str | None = field(default=None, repr=False)
    timeout: float = 10.0
    # Pin: both set = "pinned" (mismatch aborts before auth); both None =
    # first use (TOFU, accepts whatever the server presents).
    host_key_type: str | None = None
    host_key_fingerprint: str | None = None
    # Set by run() to {"type", "fingerprint"} of the key the server presented.
    host_key_observed: dict | None = field(default=None, init=False)

    def __post_init__(self) -> None:
        if (self.host_key_type is None) != (self.host_key_fingerprint is None):
            raise ValueError("host_key_type and host_key_fingerprint go together")
        if self.auth_method == "password" and self.host_key_fingerprint is None:
            raise ValueError("auth_method='password' requires a pinned host key (never first use)")
        if self.auth_method not in ("key", "password"):
            raise ValueError(f"auth_method must be 'key' or 'password', got {self.auth_method!r}")
        if self.auth_method == "key" and not self.key_material:
            raise ValueError("auth_method='key' requires key_material")
        if self.auth_method == "password" and not self.password:
            raise ValueError("auth_method='password' requires password")

    def run(self, script: str) -> str:
        client = paramiko.SSHClient()
        policy = _HostKeyPolicy(self.host_key_fingerprint)
        client.set_missing_host_key_policy(policy)
        pinned = self.host_key_type is not None
        self.host_key_observed = None
        try:
            connect_kwargs = dict(
                hostname=self.host,
                port=self.port,
                username=self.username,
                timeout=self.timeout,
                banner_timeout=self.timeout,
                auth_timeout=self.timeout,
            )
            if self.auth_method == "key":
                connect_kwargs["pkey"] = _load_private_key(self.key_material)
            else:
                connect_kwargs["password"] = self.password
            if pinned:
                allowed = _RSA_ALGS if self.host_key_type == "ssh-rsa" else {self.host_key_type}
                connect_kwargs["disabled_algorithms"] = {"keys": [a for a in _HOST_KEY_ALGS if a not in allowed]}
            client.connect(**connect_kwargs)
        except HostKeyMismatch:
            client.close()
            raise
        except paramiko.AuthenticationException as e:
            client.close()
            raise TransportAuthError(
                f"authentication failed for {self.username}@{self.host}:{self.port}"
            ) from e
        except (paramiko.SSHException, OSError, TimeoutError) as e:
            client.close()
            if pinned and "no acceptable host key" in str(e):
                # server offers no key of the pinned type: same as a changed key
                raise HostKeyMismatch(None, None) from e
            raise TransportUnreachableError(f"could not reach {self.host}:{self.port}: {e}") from e

        self.host_key_observed = policy.observed
        try:
            stdin, stdout, stderr = client.exec_command(script, timeout=self.timeout)
            stdin.close()
            out = stdout.read().decode("utf-8", errors="replace")
            err = stderr.read().decode("utf-8", errors="replace")
            return out + err
        except Exception as e:
            raise TransportTimeoutError(f"command execution against {self.host}:{self.port} failed: {e}") from e
        finally:
            client.close()
