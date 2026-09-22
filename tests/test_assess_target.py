"""Integration coverage for POST /assessment/run against the 6 real
demo/test containers (invariant-debian-baseline, etc. -- same fixed set
the monolith's own infra/docker-compose.yml still defines and this repo
doesn't duplicate). Confirmed via a direct comparison against the
monolith's `assess_target()` for the same 6 containers (same CHECKS order
-> same status list, position by position) at the time this test was
written -- see the extraction notes in the PR/commit that added this file.

Every FAIL here is identified by `titles[0]` (the canonical wording for
that Check), not an external_id -- this service never sees a real CIS
external_id at all (see api.py's module docstring for why), and unlike
the monolith's own test suite, that means no per-document drift dict is
needed: the same 70 systemic gaps fail identically on all 6 containers
(none of the 6 Dockerfiles were ever hardened for them -- see the
monolith's docs/architecture/checks-backlog.md for the "why" of each),
plus one extra title on the 2 "ssh-bad" containers and one extra on the
2 "permissions-bad" containers, matching each container's own story.
"""

import pytest
from fastapi.testclient import TestClient

from invariant_assessment.api import app

pytestmark = pytest.mark.integration

client = TestClient(app)

# The 68 titles that fail identically on all 6 containers -- none of the
# demo/test Dockerfiles were ever hardened for these (missing packages:
# auditd/AIDE/ufw/sudo/libpam-pwquality; no real audit rules loaded; no
# systemd/journald PID 1; no bootloader; no separate /var partition; etc.).
_SYSTEMIC_FAILS = {
    "Ensure AIDE is installed",
    "Ensure a single time synchronization daemon is in use",
    "Ensure access to /etc/cron.d is configured",
    "Ensure access to /etc/cron.daily is configured",
    "Ensure access to /etc/cron.hourly is configured",
    "Ensure access to /etc/cron.monthly is configured",
    "Ensure access to /etc/cron.weekly is configured",
    "Ensure access to /etc/crontab is configured",
    "Ensure access to /etc/ssh/sshd_config is configured",
    "Ensure access to bootloader config is configured",
    "Ensure access to the su command is restricted",
    "Ensure actions as another user are always logged",
    "Ensure audit configuration files group owner is configured",
    "Ensure audit configuration files owner is configured",
    "Ensure audit log files group owner is configured",
    "Ensure audit log files mode is configured",
    "Ensure audit log files owner is configured",
    "Ensure audit log storage size is configured",
    "Ensure audit logs are not automatically deleted",
    "Ensure audit tools group owner is configured",
    "Ensure audit tools mode is configured",
    "Ensure audit tools owner is configured",
    "Ensure auditd packages are installed",
    "Ensure auditd service is enabled and active",
    "Ensure default user umask is configured",
    "Ensure events that modify date and time information are collected",
    "Ensure events that modify the sudo log file are collected",
    "Ensure events that modify the system's Mandatory Access Controls are collected",
    "Ensure journald Compress is configured",
    "Ensure journald Storage is configured",
    "Ensure journald log file rotation is configured",
    "Ensure login and logout events are collected",
    "Ensure minimum password length is configured",
    "Ensure pam_faillock module is enabled",
    "Ensure pam_pwhistory includes use_authtok",
    "Ensure pam_pwhistory module is enabled",
    "Ensure pam_pwquality module is enabled",
    "Ensure pam_unix does not include nullok",
    "Ensure pam_unix includes use_authtok",
    "Ensure password complexity is configured",
    "Ensure password expiration is configured",
    "Ensure password failed attempts lockout includes root account",
    "Ensure password history is enforced for the root user",
    "Ensure password history remember is configured",
    "Ensure password maximum sequential characters is configured",
    "Ensure password number of changed characters is configured",
    "Ensure password quality is enforced for the root user",
    "Ensure password same consecutive characters is configured",
    "Ensure separate partition exists for /var",
    "Ensure session initiation information is collected",
    "Ensure sshd Banner is configured",
    "Ensure sshd Ciphers are configured",
    "Ensure sshd ClientAliveInterval and ClientAliveCountMax are configured",
    "Ensure sshd DisableForwarding is enabled",
    "Ensure sshd MACs are configured",
    "Ensure sshd MaxAuthTries is configured",
    "Ensure sshd MaxStartups is configured",
    "Ensure sshd access is configured",
    "Ensure successful file system mounts are collected",
    "Ensure sudo commands use pty",
    "Ensure sudo is installed",
    "Ensure sudo log file exists",
    "Ensure system is disabled when audit logs are full",
    "Ensure system warns when audit logs are low on space",
    "Ensure systemd-timesyncd configured with authorized timeserver",
    "Ensure the audit configuration is immutable",
    "Ensure the audit log file directory mode is configured",
    "Ensure the running and on disk configuration is the same",
    "Ensure ufw is installed",
    "Ensure unsuccessful file access attempts are collected",
}


def _assert_fails_only(target: str, expected_extra: set[str]) -> None:
    resp = client.post("/assessment/run", params={"target": target})
    assert resp.status_code == 200
    data = resp.json()

    expected = _SYSTEMIC_FAILS | expected_extra
    statuses = {r["titles"][0]: r["status"] for r in data["results"]}

    assert len(statuses) == 199
    for title in expected:
        assert statuses[title] == "FAIL", f"expected {title!r} to FAIL, got {statuses[title]!r}"
    assert all(status == "PASS" for title, status in statuses.items() if title not in expected)


def test_debian_baseline_fails_only_systemic_gaps():
    _assert_fails_only("invariant-debian-baseline", set())


def test_debian_ssh_bad_fails_permit_root_login_too():
    _assert_fails_only("invariant-debian-ssh-bad", {"Ensure sshd PermitRootLogin is disabled"})


def test_debian_permissions_bad_fails_shadow_permissions_too():
    _assert_fails_only(
        "invariant-debian-permissions-bad", {"Ensure permissions on /etc/shadow are configured"}
    )


def test_ubuntu_baseline_fails_only_systemic_gaps():
    _assert_fails_only("invariant-ubuntu-baseline", set())


def test_ubuntu_ssh_bad_fails_permit_root_login_too():
    _assert_fails_only("invariant-ubuntu-ssh-bad", {"Ensure sshd PermitRootLogin is disabled"})


def test_ubuntu_permissions_bad_fails_shadow_permissions_too():
    _assert_fails_only(
        "invariant-ubuntu-permissions-bad", {"Ensure permissions on /etc/shadow are configured"}
    )


def test_healthz():
    resp = client.get("/healthz")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


def test_unknown_os_returns_422(monkeypatch):
    """collect_facts() against a target whose /etc/os-release doesn't parse
    (or isn't Debian/Ubuntu) should surface as a client error, not a crash.
    """
    from invariant_assessment.facts import SystemFacts

    def fake_collect_facts(target):
        return SystemFacts(os_id=None, os_version_id=None, sshd_config={}, file_stats={})

    monkeypatch.setattr("invariant_assessment.api.collect_facts", fake_collect_facts)
    resp = client.post("/assessment/run", params={"target": "some-unknown-target"})
    assert resp.status_code == 422


def test_unknown_family_returns_422(monkeypatch):
    """A target whose OS is detected fine (os_id/os_version_id populated)
    but has no known Check.family group -- e.g. Windows, not implemented
    yet -- should also surface as a client error, not run zero checks
    silently or crash.
    """
    from invariant_assessment.facts import SystemFacts

    def fake_collect_facts(target):
        return SystemFacts(
            os_id="windows", os_version_id="2022", sshd_config={}, file_stats={}
        )

    monkeypatch.setattr("invariant_assessment.api.collect_facts", fake_collect_facts)
    resp = client.post("/assessment/run", params={"target": "some-windows-target"})
    assert resp.status_code == 422
    assert "windows" in resp.json()["detail"]
