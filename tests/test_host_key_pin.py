"""INV-12: SSH host key pinning. Real paramiko client against a real paramiko
SSH server running in a local thread (127.0.0.1, random port, throwaway
keys generated here). The server records every auth request it receives,
which is how the tests prove a rejected host key means no credential was
ever sent. Needs neither Docker nor the shared ssh-target fixture.
"""

import io
import socket
import threading
from types import SimpleNamespace

import paramiko
import pytest
from conftest import AUTH_HEADERS
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from fastapi.testclient import TestClient

from invariant_assessment import api
from invariant_assessment.transport import HostKeyMismatch, SSHTransport, host_key_fingerprint

client = TestClient(api.app, headers=AUTH_HEADERS)
PASSWORD = "throwaway-" + "p" * 12


def _ed25519():
    return paramiko.Ed25519Key.from_private_key(io.StringIO(_ed25519_pem()))


def _ed25519_pem() -> str:
    return (
        ed25519.Ed25519PrivateKey.generate()
        .private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.OpenSSH, serialization.NoEncryption()
        )
        .decode()
    )


_KEYS = {
    "ssh-ed25519": _ed25519,
    "ecdsa-sha2-nistp256": lambda: paramiko.ECDSAKey.generate(bits=256),
    "ssh-rsa": lambda: paramiko.RSAKey.generate(2048),
}


class _Iface(paramiko.ServerInterface):
    def __init__(self, attempts):
        self.attempts = attempts

    def get_allowed_auths(self, username):
        return "password,publickey"

    def check_auth_none(self, username):
        self.attempts.append("none")
        return paramiko.AUTH_FAILED

    def check_auth_password(self, username, password):
        self.attempts.append("password")
        return paramiko.AUTH_SUCCESSFUL if password == PASSWORD else paramiko.AUTH_FAILED

    def check_auth_publickey(self, username, key):
        self.attempts.append("publickey")
        return paramiko.AUTH_SUCCESSFUL

    def check_channel_request(self, kind, chanid):
        return paramiko.OPEN_SUCCEEDED

    def check_channel_exec_request(self, channel, command):
        def reply():
            channel.send(b"ok\n")
            channel.send_exit_status(0)
            channel.close()

        threading.Timer(0.05, reply).start()  # after the exec request is acked
        return True


class FakeSshd:
    """Offers `host_keys` (list of PKey); `attempts` lists auth requests received."""

    def __init__(self, host_keys):
        self.host_keys = host_keys
        self.attempts: list[str] = []
        self._sock = socket.socket()
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen(5)
        self._sock.settimeout(0.2)
        self.port = self._sock.getsockname()[1]
        self._stop = False
        self._transports = []
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def _loop(self):
        while not self._stop:
            try:
                conn, _ = self._sock.accept()
            except OSError:
                continue
            t = paramiko.Transport(conn)
            for k in self.host_keys:
                t.add_server_key(k)
            self._transports.append(t)
            try:
                t.start_server(server=_Iface(self.attempts))
            except paramiko.SSHException:
                pass  # client refused / no common host key: expected in some tests

    def close(self):
        self._stop = True
        self._thread.join()
        self._sock.close()
        for t in self._transports:
            t.close()


@pytest.fixture
def sshd_factory():
    started = []

    def make(*keys):
        s = FakeSshd(list(keys))
        started.append(s)
        return s

    yield make
    for s in started:
        s.close()


def _fp(key) -> str:
    return host_key_fingerprint(key)


def _tr(sshd, key_type=None, fp=None, auth="password"):
    kw = dict(host="127.0.0.1", port=sshd.port, username="u", auth_method=auth, timeout=5.0)
    if auth == "password":
        kw["password"] = PASSWORD
    else:
        kw["key_material"] = _ed25519_pem()
    return SSHTransport(host_key_type=key_type, host_key_fingerprint=fp, **kw)


@pytest.mark.parametrize("key_type", list(_KEYS))
def test_pinned_correct_fingerprint_connects(sshd_factory, key_type):
    key = _KEYS[key_type]()
    sshd = sshd_factory(key)
    t = _tr(sshd, key_type, _fp(key))
    assert t.run("true").strip() == "ok"
    assert t.host_key_observed == {"type": key.get_name(), "fingerprint": _fp(key)}


def test_pinned_rsa_wins_even_if_server_also_offers_ed25519(sshd_factory):
    rsa, ed = _KEYS["ssh-rsa"](), _ed25519()
    sshd = sshd_factory(ed, rsa)
    t = _tr(sshd, "ssh-rsa", _fp(rsa))
    t.run("true")
    assert t.host_key_observed["type"] == "ssh-rsa"


@pytest.mark.parametrize("auth", ["password", "key"])
def test_wrong_fingerprint_refused_before_any_auth(sshd_factory, auth):
    key, other = _ed25519(), _ed25519()
    sshd = sshd_factory(key)
    t = _tr(sshd, "ssh-ed25519", _fp(other), auth=auth)
    with pytest.raises(HostKeyMismatch) as exc:
        t.run("true")
    assert (exc.value.key_type, exc.value.fingerprint) == ("ssh-ed25519", _fp(key))
    assert sshd.attempts == []  # not even "none": no auth request reached the server
    assert PASSWORD not in str(exc.value)


def test_regenerated_host_key_refused_after_pinning(sshd_factory):
    old = _ed25519()
    first = sshd_factory(old)
    pinned = _tr(first, None, None, auth="key")
    pinned.run("true")
    fp = pinned.host_key_observed["fingerprint"]  # what the api would store
    assert fp == _fp(old)
    again = sshd_factory(_ed25519())  # same "host", new key
    with pytest.raises(HostKeyMismatch):
        _tr(again, "ssh-ed25519", fp, auth="key").run("true")
    assert again.attempts == []


def test_server_with_only_rsa_refused_when_ed25519_pinned(sshd_factory):
    sshd = sshd_factory(_KEYS["ssh-rsa"]())
    with pytest.raises(HostKeyMismatch) as exc:
        _tr(sshd, "ssh-ed25519", _fp(_ed25519())).run("true")
    assert (exc.value.key_type, exc.value.fingerprint) == (None, None)
    assert sshd.attempts == []


def test_first_use_returns_seen_key_and_prefers_ed25519(sshd_factory):
    ed = _ed25519()
    sshd = sshd_factory(_KEYS["ssh-rsa"](), _KEYS["ecdsa-sha2-nistp256"](), ed)
    t = _tr(sshd, auth="key")
    t.run("true")
    assert t.host_key_observed == {"type": "ssh-ed25519", "fingerprint": _fp(ed)}


def test_transport_rejects_password_without_pin():
    with pytest.raises(ValueError):
        SSHTransport(host="h", port=22, username="u", auth_method="password", password="x")


# --- HTTP layer ------------------------------------------------------------


@pytest.fixture(autouse=True)
def _fake_facts(monkeypatch):
    def fake(transport):
        transport.run("true")
        return SimpleNamespace(os_id="debian", os_version_id="12", hostname_probe_raw="h")

    monkeypatch.setattr(api, "collect_facts", fake)


def _body(sshd, **extra):
    base = {"host": "127.0.0.1", "port": sshd.port, "username": "u", "auth_method": "key", "key_material": _ed25519_pem()}
    return {**base, **extra}


def test_http_old_payload_is_first_use(sshd_factory):
    key = _ed25519()
    r = client.post("/assessment/check-remote", json=_body(sshd_factory(key)))
    assert r.status_code == 200, r.text
    d = r.json()
    assert d["host_key_verification"] == "first_use"
    assert d["host_key_observed"] == {"type": "ssh-ed25519", "fingerprint": _fp(key)}


def test_http_explicit_first_use_and_run_remote(sshd_factory, monkeypatch):
    # the real check engine needs real facts; here only the host key fields matter
    monkeypatch.setattr(api, "_evaluate_all", lambda facts, label, extra=None: api.RunResponse(document="d", results=[], **extra))
    r = client.post("/assessment/run-remote", json=_body(sshd_factory(_ed25519()), host_key_mode="first_use"))
    assert r.status_code == 200, r.text
    assert r.json()["host_key_verification"] == "first_use"


def test_http_pinned_without_mode_is_operator(sshd_factory):
    key = _ed25519()
    body = _body(sshd_factory(key), host_key_type="ssh-ed25519", host_key_fingerprint=_fp(key))
    r = client.post("/assessment/check-remote", json=body)
    assert r.status_code == 200, r.text
    assert r.json()["host_key_verification"] == "operator"
    assert r.json()["host_key_observed"]["fingerprint"] == _fp(key)


@pytest.mark.parametrize("path", ["/assessment/check-remote", "/assessment/run-remote"])
def test_http_mismatch_is_409_with_only_seen_key(sshd_factory, path):
    key = _ed25519()
    sshd = sshd_factory(key)
    body = _body(sshd, auth_method="password", key_material=None, password=PASSWORD,
                 host_key_type="ssh-ed25519", host_key_fingerprint=_fp(_ed25519()))
    r = client.post(path, json=body)
    assert r.status_code == 409
    assert r.json()["detail"] == {
        "code": "host_key_mismatch",
        "host_key_observed": {"type": "ssh-ed25519", "fingerprint": _fp(key)},
    }
    assert PASSWORD not in r.text
    assert sshd.attempts == []


def test_http_rsa_only_server_with_ed25519_pin_is_409_null_observed(sshd_factory):
    body = _body(sshd_factory(_KEYS["ssh-rsa"]()), host_key_type="ssh-ed25519", host_key_fingerprint=_fp(_ed25519()))
    r = client.post("/assessment/check-remote", json=body)
    assert r.status_code == 409
    assert r.json()["detail"]["host_key_observed"] == {"type": None, "fingerprint": None}


FP = "SHA256:" + "A" * 43


@pytest.mark.parametrize(
    "extra",
    [
        {"auth_method": "password", "key_material": None, "password": "x"},  # password needs a pin
        {"auth_method": "password", "key_material": None, "password": "x", "host_key_mode": "first_use"},
        {"host_key_type": "ssh-ed25519"},  # type without fingerprint
        {"host_key_fingerprint": FP},  # fingerprint without type
        {"host_key_mode": "pinned"},
        {"host_key_mode": "first_use", "host_key_type": "ssh-ed25519", "host_key_fingerprint": FP},
        {"host_key_type": "ssh-ed25519", "host_key_fingerprint": "SHA256:short"},
        {"host_key_type": "ssh-dss", "host_key_fingerprint": FP},
    ],
)
def test_http_invalid_host_key_payloads_are_422(extra):
    body = {"host": "127.0.0.1", "port": 1, "username": "u", "auth_method": "key", "key_material": "k", **extra}
    for path in ("/assessment/check-remote", "/assessment/run-remote"):
        assert client.post(path, json=body).status_code == 422


@pytest.mark.parametrize("path", ["/assessment/check-remote", "/assessment/run-remote"])
@pytest.mark.parametrize(
    "extra",
    [{}, {"host_key_type": "ssh-ed25519", "host_key_fingerprint": "SHA256:short"}],
)
def test_422_never_echoes_secrets(path, extra):
    pw, key = "MARKER-PASSWORD-" + "q" * 8, "MARKER-KEY-MATERIAL-" + "z" * 8
    body = {"host": "h", "username": "u", "auth_method": "password", "password": pw, "key_material": key, **extra}
    r = client.post(path, json=body)
    assert r.status_code == 422
    assert pw not in r.text and key not in r.text
    assert all(set(item) == {"loc", "msg", "type"} for item in r.json()["detail"])
