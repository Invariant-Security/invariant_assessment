"""INV-49 over real SSH, logged in as a non-root user on a host with sshd and
auditd (fixture ssh-target-nonroot). Checks that need root come back
NOT_ASSESSED, never PASS/FAIL."""

import socket
from collections import Counter

import paramiko
import pytest
from conftest import AUTH_HEADERS, SSH_TARGET_NONROOT_PORT
from fastapi.testclient import TestClient

from invariant_assessment.api import app
from invariant_assessment.transport import host_key_fingerprint

pytestmark = pytest.mark.integration

client = TestClient(app, headers=AUTH_HEADERS)

_HOST, _PORT = "127.0.0.1", SSH_TARGET_NONROOT_PORT
_USER, _PASSWORD = "invariant-nonroot", "invariant-nonroot-password"


def _pin() -> dict:
    with socket.create_connection((_HOST, _PORT), timeout=5) as sock:
        t = paramiko.Transport(sock)
        try:
            t.start_client(timeout=5)
            key = t.get_remote_server_key()
            return {"host_key_type": key.get_name(), "host_key_fingerprint": host_key_fingerprint(key)}
        finally:
            t.close()


def test_nonroot_ssh_full_run_marks_unreadable_checks_not_assessed():
    body = {"host": _HOST, "port": _PORT, "username": _USER, "auth_method": "password", "password": _PASSWORD, **_pin()}
    resp = client.post("/assessment/run-remote", json=body)
    assert resp.status_code == 200, resp.text
    results = {r["check_id"]: r for r in resp.json()["results"]}
    assert len(results) == 199
    assert Counter(r["status"] for r in results.values())["NOT_ASSESSED"] > 0
    assert set(r["status"] for r in results.values()) <= {"PASS", "FAIL", "NOT_ASSESSED"}
    # sshd -T and /etc/shadow need root
    assert results["ssh_permit_root_login"]["status"] == "NOT_ASSESSED"
    assert results["shadow_password_fields_not_empty"]["status"] == "NOT_ASSESSED"
    # /etc/audit is 0750 root: the rules.d glob must not read as "no rules"
    for r in results.values():
        if r["status"] == "NOT_ASSESSED":
            assert r["evidence"].startswith("not assessed: ") and "not readable" in r["evidence"]


def test_nonroot_ssh_audit_sync_check_not_assessed_not_false_fail():
    """INV-59: an SSH session has no /sbin in PATH, so `augenrules` was "not
    found" and the check read as FAIL on a host that has auditd. With sbin in
    the collector's PATH the tool runs; /etc/audit is root-only, so the honest
    answer for this user is NOT_ASSESSED."""
    body = {"host": _HOST, "port": _PORT, "username": _USER, "auth_method": "password", "password": _PASSWORD, **_pin()}
    resp = client.post("/assessment/run-remote", json=body)
    assert resp.status_code == 200, resp.text
    r = {x["check_id"]: x for x in resp.json()["results"]}["audit_rules_running_matches_disk"]
    assert r["status"] == "NOT_ASSESSED", r
    assert "augenrules: not found" not in r["evidence"]
