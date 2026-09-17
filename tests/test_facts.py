import pytest

from invariant_assessment.facts import (
    _MARKER_OS_RELEASE,
    _MARKER_SSHD_CONFIG,
    _MARKER_STAT_PREFIX,
    _STAT_PATHS,
    _TEXT_BLOCKS,
    _collect_script,
    _parse_collect_output,
    _parse_installed_packages,
    _parse_stat_line,
    clean_hostname,
    is_running_in_container,
    parse_sshd_config,
)


def _build_full_output(overrides: dict[str, str] | None = None) -> str:
    """Builds a synthetic docker-exec output matching what _collect_script()
    produces, driven off the real marker lists so this fixture doesn't rot
    as more text blocks / stat paths are added.
    """
    overrides = overrides or {}
    parts = [f"{_MARKER_OS_RELEASE}\nID=debian\nVERSION_ID=\"11\"\n"]
    parts.append(f"{_MARKER_SSHD_CONFIG}\nPermitRootLogin no\n")
    for attr, marker, _cmd in _TEXT_BLOCKS:
        parts.append(f"{marker}\n{overrides.get(attr, '')}\n")
    for path in _STAT_PATHS:
        parts.append(f"{_MARKER_STAT_PREFIX}{path}===\nmode=640 uid=0 gid=42 gname=shadow\n")
    return "".join(parts)


def test_parse_sshd_config_lowercases_directives():
    text = "PermitRootLogin no\nPasswordAuthentication yes\n"
    assert parse_sshd_config(text) == {"permitrootlogin": "no", "passwordauthentication": "yes"}


def test_parse_sshd_config_skips_comments_and_blank_lines():
    text = "# this is a comment\n\nPermitRootLogin no\n   \n"
    assert parse_sshd_config(text) == {"permitrootlogin": "no"}


def test_parse_sshd_config_later_line_wins_on_duplicate():
    text = "PermitRootLogin no\nPermitRootLogin yes\n"
    assert parse_sshd_config(text) == {"permitrootlogin": "yes"}


def test_parse_stat_line_extracts_mode_uid_gid():
    stat = _parse_stat_line("mode=640 uid=0 gid=42 gname=shadow")
    assert stat.mode == 0o640
    assert stat.uid == 0
    assert stat.gid == 42
    assert stat.gname == "shadow"


def test_parse_stat_line_returns_none_fields_on_stat_error():
    stat = _parse_stat_line("stat: cannot statx '/etc/shadow': No such file or directory")
    assert stat.mode is None
    assert stat.uid is None


def test_parse_installed_packages_splits_lines_and_strips_blank():
    assert _parse_installed_packages("bash\n\ncoreutils\n") == {"bash", "coreutils"}


def test_parse_installed_packages_empty_on_no_output():
    assert _parse_installed_packages("") == set()


def test_collect_script_invokes_sshd_by_absolute_path():
    # Regression: caught live against a real SSH-reached host where sshd
    # was genuinely installed and actively serving the connection --
    # PATH for an unprivileged non-login shell excludes /usr/sbin, so a
    # bare `sshd -T` failed with "command not found" and was misread as
    # sshd being ABSENT. Debian/Ubuntu (the only supported family) always
    # ships sshd at this exact path.
    assert "/usr/sbin/sshd -T" in _collect_script()
    assert "; sshd -T" not in _collect_script()  # never the bare, PATH-dependent form


def test_clean_hostname_accepts_a_real_single_word_hostname():
    assert clean_hostname("invariant-demo-linux\n") == "invariant-demo-linux"


def test_clean_hostname_rejects_empty_output():
    assert clean_hostname("") is None
    assert clean_hostname("   \n") is None


def test_clean_hostname_rejects_error_text():
    assert clean_hostname("cat: /etc/hostname: No such file or directory") is None
    assert clean_hostname("cat: /etc/hostname: Permission denied") is None


def test_parse_collect_output_extracts_hostname():
    output = _build_full_output({"hostname_probe_raw": "invariant-demo-linux"})

    facts = _parse_collect_output(output)

    assert clean_hostname(facts.hostname_probe_raw) == "invariant-demo-linux"


def test_parse_collect_output_full_script_output():
    output = _build_full_output(
        {
            "passwd_text": "root:x:0:0:root:/root:/bin/bash",
            "installed_packages_text": "bash\ncoreutils\nopenssh-server\n",
        }
    )

    facts = _parse_collect_output(output)

    assert facts.os_id == "debian"
    assert facts.os_version_id == "11"
    assert facts.sshd_config == {"permitrootlogin": "no"}
    assert facts.file_stats["/etc/shadow"].mode == 0o640
    assert facts.passwd_text == "root:x:0:0:root:/root:/bin/bash"
    assert facts.installed_packages == {"bash", "coreutils", "openssh-server"}


def test_parse_collect_output_text_block_defaults_to_empty_string():
    output = _build_full_output()

    facts = _parse_collect_output(output)

    assert facts.group_text == ""
    assert facts.pam_common_auth == ""
    assert facts.login_defs_text == ""


def test_parse_collect_output_raises_when_markers_missing():
    with pytest.raises(LookupError):
        _parse_collect_output("Error response from daemon: No such container: nope\n")


def test_is_running_in_container_detects_dockerenv():
    facts = _parse_collect_output(
        _build_full_output({"container_detection_text": "/.dockerenv:present\n0::/"})
    )
    assert is_running_in_container(facts) is True


def test_is_running_in_container_detects_cgroup_marker():
    facts = _parse_collect_output(
        _build_full_output({"container_detection_text": "/.dockerenv:absent\n0::/docker/abc123"})
    )
    assert is_running_in_container(facts) is True


def test_is_running_in_container_false_on_bare_metal():
    facts = _parse_collect_output(
        _build_full_output({"container_detection_text": "/.dockerenv:absent\n0::/"})
    )
    assert is_running_in_container(facts) is False


def test_audit_conf_text_stat_command_includes_all_six_audit_tools():
    """Regression: the stat command must check /sbin/autrace alongside the
    other 5 audit tools -- checking one extra binary's mode is a harmless
    superset (missing means no entry, see _parse_stat_lines), and fixes a
    genuine under-check on the 5 of 6 real target documents that do require
    it."""
    (_, _, cmd), = [block for block in _TEXT_BLOCKS if block[0] == "audit_conf_text"]
    for tool in ("auditctl", "aureport", "ausearch", "auditd", "augenrules", "autrace"):
        assert f"/sbin/{tool}" in cmd


def test_audit_conf_text_logdir_never_falls_back_to_cwd_when_auditd_is_absent(tmp_path):
    """Regression for a real leak found via the public demo snapshot: when
    /etc/audit/auditd.conf is missing (or has no log_file directive, same
    as "auditd not installed"), the LOGDIR section used to run `dirname ""`
    -- which returns "." (the shell's cwd), not empty -- so the guard below
    it passed and `find .` listed whatever was in the docker-exec session's
    working directory (the target's WORKDIR) instead of reporting
    LOGDIR_NOT_FOUND. Confirmed live on a container without auditd: real
    project files (to-do.md, alembic.ini, ...) showed up as "audit log
    files". This runs the actual collected shell fragment (not a container,
    just `sh -c`) from a scratch cwd salted with decoy files that must never
    appear in the output.
    """
    import subprocess

    (_, marker, cmd), = [block for block in _TEXT_BLOCKS if block[0] == "audit_conf_text"]

    decoy = tmp_path / "top-secret-project-file.md"
    decoy.write_text("should never be listed")

    result = subprocess.run(["sh", "-c", cmd], cwd=tmp_path, capture_output=True, text=True, timeout=10)
    output = result.stdout

    assert "LOGDIR_NOT_FOUND" in output
    assert "top-secret-project-file.md" not in output
    # marker itself is just the section header used to slice the real
    # collect_script() output -- sanity-check it's actually present so this
    # test would fail loudly if _TEXT_BLOCKS' shape ever changes underneath it.
    assert marker
