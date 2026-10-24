"""INV-49: a fact the collector could not read is "not assessed", never PASS/FAIL."""

import pytest

from invariant_assessment import CHECKS, Check
from invariant_assessment.facts import (
    _MARKER_OS_RELEASE,
    _MARKER_SSHD_CONFIG,
    _MARKER_STAT_PREFIX,
    _STAT_PATHS,
    _TEXT_BLOCKS,
    _collect_script,
    _parse_collect_output,
    evaluate_check,
)


def _out(blocks=None, stats=None, sshd="PermitRootLogin no", sshd_rc=0):
    """Synthetic collector output; blocks: attr -> (text, rc), stats: path -> (text, rc)."""
    blocks, stats = blocks or {}, stats or {}
    rc = lambda n: f"\n===RC={n}===\n"
    parts = [f"{_MARKER_OS_RELEASE}\nID=debian\nVERSION_ID=\"11\"\n"]
    parts.append(f"{_MARKER_SSHD_CONFIG}\n{sshd}{rc(sshd_rc)}")
    for attr, marker, _ in _TEXT_BLOCKS:
        text, n = blocks.get(attr, ("", 0))
        parts.append(f"{marker}\n{text}{rc(n)}")
    for p in _STAT_PATHS:
        text, n = stats.get(p, ("mode=640 uid=0 gid=42 gname=shadow", 0))
        parts.append(f"{_MARKER_STAT_PREFIX}{p}===\n{text}{rc(n)}")
    return "".join(parts)


def _facts(**kw):
    return _parse_collect_output(_out(**kw))


def test_script_forces_c_locale_and_merges_stderr():
    s = _collect_script()
    assert s.startswith("export LC_ALL=C; exec 2>&1;")
    assert "RC=%s" in s


@pytest.mark.parametrize(
    "msg",
    [
        "cat: /etc/shadow: Permission denied",
        "cat: /etc/sudoers: Operation not permitted",
        "augenrules: You must be root to run this program.",
    ],
)
def test_unreadable_patterns(msg):
    f = _facts(blocks={"shadow_text": (msg, 1)})
    assert "shadow_text" in f.unreadable and "shadow_text" not in f.missing


def test_unreadable_reports_the_path():
    f = _facts(blocks={"shadow_text": ("cat: /etc/shadow: Permission denied", 1)})
    assert f.unreadable["shadow_text"] == "/etc/shadow not readable (permission denied)"


def test_missing_is_recorded_but_not_unreadable():
    f = _facts(blocks={"pwhistory_text": ("cat: /etc/security/pwhistory.conf: No such file or directory", 1)})
    assert "pwhistory_text" in f.missing and "pwhistory_text" not in f.unreadable


def test_glob_directory_guard_is_in_the_script_and_reported():
    s = _collect_script()
    assert "[ -d /etc/audit/rules.d ]" in s and "[ -x /etc/audit/rules.d ]" in s
    # what the guard prints when the directory is 0750 non-root, next to the shell's literal-glob error
    text = "/etc/audit/rules.d: Permission denied\ncat: '/etc/audit/rules.d/*.rules': No such file or directory"
    f = _facts(blocks={"audit_rules_text": (text, 1)})
    assert "audit_rules_text" in f.unreadable and "audit_rules_text" not in f.missing


def test_root_only_probe_guard_is_in_the_script():
    assert "You must be root" in _collect_script()


def test_unrecognized_failure_in_plain_cat_is_unreadable():
    f = _facts(blocks={"passwd_text": ("cat: /etc/passwd: Is a directory", 1)})
    assert "passwd_text" in f.unreadable


@pytest.mark.parametrize(
    "attr,text,rc",
    [
        ("journal_remote_status_text", "", 1),  # grep without a match
        ("boot_grub_audit_text", "", 1),
        ("systemd_service_status_text", "--AUDITD_ENABLED--\ndisabled\n--AUDITD_ACTIVE--\ninactive", 3),
        ("audit_rules_sync_text", "No change", 1),  # augenrules --check exit status carries data
        ("mounts_text", "", 1),  # findmnt of a path that is not a mount
        ("hostname_probe_raw", "myhost", 0),
        ("passwd_text", "", 1),  # no output at all: nothing to classify
    ],
)
def test_legit_nonzero_or_quiet_is_not_flagged(attr, text, rc):
    f = _facts(blocks={attr: (text, rc)})
    assert not f.unreadable and not f.missing


def test_sshd_probe_outcomes():
    nr = _facts(sshd="sshd: no hostkeys available -- exiting.", sshd_rc=1)
    assert {"sshd_config", "sshd_probe_raw"} <= set(nr.unreadable)
    gone = _facts(sshd="sh: 1: /usr/sbin/sshd: not found", sshd_rc=127)
    assert not gone.unreadable and "sshd_config" in gone.missing
    odd = _facts(sshd="sshd: /etc/ssh/sshd_config line 3: Bad configuration option", sshd_rc=255)
    assert not odd.unreadable  # other failures keep the <sshd-status-unknown> sentinel


def test_file_stats_unreadable_per_path():
    f = _facts(stats={"/etc/audit/audit.rules": ("stat: cannot statx '/etc/audit/audit.rules': Permission denied", 1),
                      "/etc/motd": ("stat: cannot statx '/etc/motd': No such file or directory", 1)})
    assert list(f.unreadable) == ["file_stats:/etc/audit/audit.rules"]
    assert f.missing == {"file_stats:/etc/motd"}
    assert f.file_stats["/etc/motd"].mode is None


def test_rc_lines_do_not_leak_into_values():
    f = _facts(blocks={"passwd_text": ("root:x:0:0", 0)})
    assert f.passwd_text == "root:x:0:0"


def _check(fn):
    return Check(id="t", evaluate=fn, evidence=lambda f: "ev")


def test_proxy_marks_only_when_an_accessed_field_is_unreadable():
    f = _facts(blocks={"shadow_text": ("cat: /etc/shadow: Permission denied", 1)})
    assert evaluate_check(_check(lambda x: "root" in x.passwd_text), f)["status"] == "FAIL"
    r = evaluate_check(_check(lambda x: "root" in x.shadow_text), f)
    assert r == {"status": "NOT_ASSESSED", "evidence": "not assessed: /etc/shadow not readable (permission denied)"}


def test_proxy_file_stats_per_path():
    f = _facts(stats={"/etc/audit/audit.rules": ("stat: cannot statx '/etc/audit/audit.rules': Permission denied", 1)})
    assert evaluate_check(_check(lambda x: x.file_stats.get("/etc/motd").mode == 0o640), f)["status"] == "PASS"
    assert evaluate_check(_check(lambda x: x.file_stats.get("/etc/audit/audit.rules") is not None), f)["status"] == "NOT_ASSESSED"
    assert evaluate_check(_check(lambda x: len(list(x.file_stats.items()))), f)["status"] == "NOT_ASSESSED"


def test_sshd_check_is_not_assessed_without_root():
    f = _facts(sshd="sshd: no hostkeys available -- exiting.", sshd_rc=1)
    check = next(c for c in CHECKS if c.id == "ssh_permit_root_login")
    assert evaluate_check(check, f)["status"] == "NOT_ASSESSED"


def test_no_benchmark_wording_in_not_assessed_evidence():
    f = _facts(blocks={"shadow_text": ("cat: /etc/shadow: Permission denied", 1)})
    r = evaluate_check(_check(lambda x: x.shadow_text), f)
    assert r["evidence"].startswith("not assessed: ") and "benchmark" not in r["evidence"].lower()
