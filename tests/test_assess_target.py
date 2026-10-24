"""Integration coverage for POST /assessment/run against the 6 real
demo/test containers (invariant-debian-baseline, etc.). Every FAIL here is
identified by the Check's `check_id` -- this service never sees a real
external_id at all (see api.py's module docstring for why): the same
systemic gaps fail identically on all 6 containers (none of the 6
Dockerfiles were ever hardened for them), plus one extra check on the 2
"ssh-bad" containers and one extra on the 2 "permissions-bad" containers,
matching each container's own story.
"""

import pytest
from conftest import AUTH_HEADERS, FIXTURE_PREFIX
from fastapi.testclient import TestClient

from invariant_assessment.api import app

pytestmark = pytest.mark.integration

client = TestClient(app, headers=AUTH_HEADERS)

# The 71 check ids that fail identically on all 6 containers -- none of the
# demo/test Dockerfiles were ever hardened for these (missing packages:
# auditd/AIDE/ufw/sudo/libpam-pwquality; no audit rules loaded; no
# systemd/journald PID 1; no bootloader; no separate /var partition; etc.).
_SYSTEMIC_FAILS = {
    "aide_installed",
    "faillock_unlock_time",
    "single_time_sync_daemon",
    "cron_d_permissions",
    "cron_daily_permissions",
    "cron_hourly_permissions",
    "cron_monthly_permissions",
    "cron_weekly_permissions",
    "etc_crontab_permissions",
    "etc_ssh_sshd_config_permissions",
    "bootloader_config_permissions",
    "su_restricted",
    "user_emulation_logged",
    "audit_conf_files_group_owner",
    "audit_conf_files_owner",
    "audit_log_files_group_owner",
    "audit_log_files_mode",
    "audit_log_files_owner",
    "audit_log_storage_size",
    "audit_logs_not_auto_deleted",
    "audit_tools_group_owner",
    "audit_tools_mode",
    "audit_tools_owner",
    "auditd_packages_installed",
    "auditd_enabled_active",
    "default_umask",
    "time_change_logged",
    "sudo_log_file_logged",
    "mac_policy_logged",
    "journald_compress",
    "journald_storage",
    "journald_log_rotation",
    "logins_logged",
    "pwquality_minlen",
    "pam_faillock_enabled",
    "pam_pwhistory_use_authtok",
    "pam_pwhistory_enabled",
    "pam_pwquality_enabled",
    "pam_no_nullok",
    "pam_unix_use_authtok",
    "pwquality_complexity",
    "password_expiration_configured",
    "faillock_root_lockout",
    "pwhistory_enforce_for_root",
    "pwhistory_remember",
    "pwquality_max_sequence",
    "pwquality_difok",
    "pwquality_enforce_for_root",
    "pwquality_max_repeat",
    "mount_var_separate",
    "session_logged",
    "ssh_banner",
    "ssh_ciphers",
    "ssh_client_alive",
    "ssh_disable_forwarding",
    "ssh_macs",
    "ssh_max_auth_tries",
    "ssh_max_startups",
    "ssh_allow_deny_configured",
    "mounts_logged",
    "sudo_use_pty",
    "sudo_installed",
    "sudo_log_file_exists",
    "audit_disk_full_error_actions",
    "audit_space_left_actions",
    "timesyncd_authorized_timeserver",
    "audit_config_immutable",
    "audit_log_dir_mode",
    "audit_rules_running_matches_disk",
    "ufw_installed",
    "unsuccessful_file_access_logged",
}


def _assert_fails_only(target: str, expected_extra: set[str]) -> None:
    resp = client.post("/assessment/run", params={"target": target})
    assert resp.status_code == 200
    data = resp.json()

    expected = _SYSTEMIC_FAILS | expected_extra
    statuses = {r["check_id"]: r["status"] for r in data["results"]}

    assert len(statuses) == 199
    for check_id in expected:
        assert statuses[check_id] == "FAIL", f"expected {check_id!r} to FAIL, got {statuses[check_id]!r}"
    assert all(status == "PASS" for check_id, status in statuses.items() if check_id not in expected)


def test_debian_baseline_fails_only_systemic_gaps():
    _assert_fails_only(f"{FIXTURE_PREFIX}-debian-baseline", set())


def test_debian_ssh_bad_fails_permit_root_login_too():
    _assert_fails_only(f"{FIXTURE_PREFIX}-debian-ssh-bad", {"ssh_permit_root_login"})


def test_debian_permissions_bad_fails_shadow_permissions_too():
    _assert_fails_only(
        f"{FIXTURE_PREFIX}-debian-permissions-bad", {"etc_shadow_permissions"}
    )


def test_ubuntu_baseline_fails_only_systemic_gaps():
    _assert_fails_only(f"{FIXTURE_PREFIX}-ubuntu-baseline", set())


def test_ubuntu_ssh_bad_fails_permit_root_login_too():
    _assert_fails_only(f"{FIXTURE_PREFIX}-ubuntu-ssh-bad", {"ssh_permit_root_login"})


def test_ubuntu_permissions_bad_fails_shadow_permissions_too():
    _assert_fails_only(
        f"{FIXTURE_PREFIX}-ubuntu-permissions-bad", {"etc_shadow_permissions"}
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
