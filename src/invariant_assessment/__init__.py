"""Evaluates a target's collected SystemFacts against every implemented
check -- the `Check`/`CHECKS` half of the assessment engine, extracted
into its own service.

Deliberately has no Postgres access and no concept of a `Finding`: this
module's job stops at "which checks passed/failed, with what evidence".
api.py exposes that over HTTP (`/assessment/run`); invariant_api joins the
results against its own control catalogue.

Evidence is gathered once per target (facts.collect_facts(), a single
`docker exec` or SSH round trip) rather than once per check -- checks are
plain Python comparisons against that snapshot. No agent is installed on
the target.

The OS document a target maps to is *detected* from the collected facts,
not hardcoded (document_slug_for_os()).
"""

import re
from collections import Counter
from dataclasses import dataclass
from datetime import date, datetime, timezone
from typing import Callable

from invariant_assessment.facts import SystemFacts, collect_facts


# Real `sshd -T` success always dumps dozens of directives (~60+) -- never
# just one or two. Below that, `facts.sshd_config` isn't actually evidence
# of success: parse_sshd_config() has no way to know a line came from
# `sshd -T`'s real output rather than a shell error, so a single-line
# failure like `sh: 1: sshd: not found` parses into one bogus "directive"
# (`{"sh:": "1: sshd: not found"}`) -- confirmed live, this genuinely
# happened against a real sshd-less container. `bool(facts.sshd_config)`
# alone would have read that as "present". A small count threshold, far
# below a real config's size and far above what a one-line error could
# produce, tells them apart without needing parse_sshd_config() itself to
# know about shell error shapes.
_SSHD_CONFIG_MIN_DIRECTIVES_FOR_PRESENT = 5


def _sshd_state(facts: SystemFacts) -> str:
    """'present' | 'absent' | 'unknown'. `facts.sshd_config` alone can't
    reliably tell these apart -- see _SSHD_CONFIG_MIN_DIRECTIVES_FOR_
    PRESENT's comment for why a merely non-empty dict isn't proof `sshd -T`
    actually ran. 'present': sshd_config has real directive-count evidence
    of a genuine `sshd -T` success. 'absent': the probe failed with a
    shell "command not found"-shaped error (confirmed live: a container
    with no sshd package gives literally `sh: 1: sshd: not found`).
    'unknown': any other failure -- must never be treated as "absent"
    downstream, since that would misreport a real permission/config
    problem as "not applicable".
    """
    if len(facts.sshd_config) >= _SSHD_CONFIG_MIN_DIRECTIVES_FOR_PRESENT:
        return "present"
    probe = facts.sshd_probe_raw.lower()
    if "not found" in probe or "no such file or directory" in probe:
        return "absent"
    return "unknown"


def _sshd_directive_value(facts: SystemFacts, directive: str) -> str:
    state = _sshd_state(facts)
    if state == "absent":
        return "<sshd-not-installed>"
    if state == "unknown":
        return "<sshd-status-unknown>"
    return facts.sshd_config.get(directive, "<not set>")


def _evaluate_ssh_permit_root_login(facts: SystemFacts) -> bool:
    return facts.sshd_config.get("permitrootlogin", "").lower() == "no"


def _evidence_ssh_permit_root_login(facts: SystemFacts) -> str:
    value = _sshd_directive_value(facts, "permitrootlogin")
    return f"sshd_config: PermitRootLogin {value}"


def _evaluate_etc_shadow_permissions(facts: SystemFacts) -> bool:
    """Mode 640 or more restrictive, uid 0/root, gid 0/root or the shadow group."""
    stat = facts.file_stats.get("/etc/shadow")
    if stat is None or stat.mode is None:
        return False
    return stat.mode <= 0o640 and stat.uid == 0 and stat.gname in ("root", "shadow")


def _evidence_etc_shadow_permissions(facts: SystemFacts) -> str:
    stat = facts.file_stats.get("/etc/shadow")
    if stat is None or stat.mode is None:
        return "/etc/shadow: could not stat"
    return f"/etc/shadow: mode={oct(stat.mode)} uid={stat.uid} gid={stat.gid}({stat.gname})"


def _evaluate_ssh_permit_user_environment(facts: SystemFacts) -> bool:
    return facts.sshd_config.get("permituserenvironment", "").lower() == "no"


def _evidence_ssh_permit_user_environment(facts: SystemFacts) -> str:
    value = _sshd_directive_value(facts, "permituserenvironment")
    return f"sshd_config: PermitUserEnvironment {value}"


def _evaluate_ssh_ignore_rhosts(facts: SystemFacts) -> bool:
    return facts.sshd_config.get("ignorerhosts", "").lower() == "yes"


def _evidence_ssh_ignore_rhosts(facts: SystemFacts) -> str:
    value = _sshd_directive_value(facts, "ignorerhosts")
    return f"sshd_config: IgnoreRhosts {value}"


def _evaluate_ssh_login_grace_time(facts: SystemFacts) -> bool:
    value = facts.sshd_config.get("logingracetime", "")
    try:
        seconds = int(value)
    except ValueError:
        return False
    return 1 <= seconds <= 60


def _evidence_ssh_login_grace_time(facts: SystemFacts) -> str:
    value = _sshd_directive_value(facts, "logingracetime")
    return f"sshd_config: LoginGraceTime {value}"


def _permissions_ok(
    facts: SystemFacts, path: str, max_mode: int, allowed_gnames: tuple[str, ...]
) -> bool:
    """Shared by every plain file-permission check below (/etc/issue,
    /etc/passwd(-), /etc/group(-), /etc/shadow-, /etc/gshadow(-), /etc/shells,
    /etc/ssh/sshd_config): stat mode <= a ceiling, uid 0/root, gid 0/root or one
    allowed group, parameterised by path/mode/group.
    """
    stat = facts.file_stats.get(path)
    if stat is None or stat.mode is None:
        return False
    return stat.mode <= max_mode and stat.uid == 0 and stat.gname in allowed_gnames


def _evidence_for_stat(path: str) -> Callable[[SystemFacts], str]:
    def _evidence(facts: SystemFacts) -> str:
        stat = facts.file_stats.get(path)
        if stat is None or stat.mode is None:
            return f"{path}: could not stat"
        return f"{path}: mode={oct(stat.mode)} uid={stat.uid} gid={stat.gid}({stat.gname})"

    return _evidence


def _evaluate_etc_issue_permissions(facts: SystemFacts) -> bool:
    return _permissions_ok(facts, "/etc/issue", 0o644, ("root",))


_evidence_etc_issue_permissions = _evidence_for_stat("/etc/issue")


def _evaluate_etc_issue_net_permissions(facts: SystemFacts) -> bool:
    return _permissions_ok(facts, "/etc/issue.net", 0o644, ("root",))


_evidence_etc_issue_net_permissions = _evidence_for_stat("/etc/issue.net")


def _evaluate_etc_passwd_permissions(facts: SystemFacts) -> bool:
    return _permissions_ok(facts, "/etc/passwd", 0o644, ("root",))


_evidence_etc_passwd_permissions = _evidence_for_stat("/etc/passwd")


def _evaluate_etc_passwd_minus_permissions(facts: SystemFacts) -> bool:
    return _permissions_ok(facts, "/etc/passwd-", 0o644, ("root",))


_evidence_etc_passwd_minus_permissions = _evidence_for_stat("/etc/passwd-")


def _evaluate_etc_group_permissions(facts: SystemFacts) -> bool:
    return _permissions_ok(facts, "/etc/group", 0o644, ("root",))


_evidence_etc_group_permissions = _evidence_for_stat("/etc/group")


def _evaluate_etc_group_minus_permissions(facts: SystemFacts) -> bool:
    return _permissions_ok(facts, "/etc/group-", 0o644, ("root",))


_evidence_etc_group_minus_permissions = _evidence_for_stat("/etc/group-")


def _evaluate_etc_shadow_minus_permissions(facts: SystemFacts) -> bool:
    return _permissions_ok(facts, "/etc/shadow-", 0o640, ("root", "shadow"))


_evidence_etc_shadow_minus_permissions = _evidence_for_stat("/etc/shadow-")


def _evaluate_etc_gshadow_permissions(facts: SystemFacts) -> bool:
    return _permissions_ok(facts, "/etc/gshadow", 0o640, ("root", "shadow"))


_evidence_etc_gshadow_permissions = _evidence_for_stat("/etc/gshadow")


def _evaluate_etc_gshadow_minus_permissions(facts: SystemFacts) -> bool:
    return _permissions_ok(facts, "/etc/gshadow-", 0o640, ("root", "shadow"))


_evidence_etc_gshadow_minus_permissions = _evidence_for_stat("/etc/gshadow-")


def _evaluate_etc_shells_permissions(facts: SystemFacts) -> bool:
    return _permissions_ok(facts, "/etc/shells", 0o644, ("root",))


_evidence_etc_shells_permissions = _evidence_for_stat("/etc/shells")


def _evaluate_etc_ssh_sshd_config_permissions(facts: SystemFacts) -> bool:
    return _permissions_ok(facts, "/etc/ssh/sshd_config", 0o600, ("root",))


_evidence_etc_ssh_sshd_config_permissions = _evidence_for_stat("/etc/ssh/sshd_config")


def _passwd_fields(passwd_text: str) -> list[list[str]]:
    """Splits /etc/passwd-style text into colon-separated fields per
    non-blank line. Lines that don't parse into enough fields (a `cat`
    error message when the file couldn't be read, for instance) are
    dropped rather than raising -- same "don't crash on unreadable input"
    posture as facts.FileStat.mode being None.
    """
    rows = []
    for line in passwd_text.splitlines():
        if not line.strip():
            continue
        fields = line.split(":")
        if len(fields) < 4:
            continue
        rows.append(fields)
    return rows


def _evaluate_shadow_password_fields_not_empty(facts: SystemFacts) -> bool:
    """Every account's password field in /etc/shadow (colon field 2) must be
    non-empty: a hash or a lock marker such as `*` or `!`, never blank.
    """
    for fields in _passwd_fields(facts.shadow_text):
        if fields[1] == "":
            return False
    return True


def _evidence_shadow_password_fields_not_empty(facts: SystemFacts) -> str:
    empty_users = [f[0] for f in _passwd_fields(facts.shadow_text) if f[1] == ""]
    if empty_users:
        return f"/etc/shadow: empty password field for: {', '.join(empty_users)}"
    return "/etc/shadow: no empty password fields"


def _evaluate_passwd_accounts_use_shadowed_passwords(facts: SystemFacts) -> bool:
    """Every account's password field in /etc/passwd (colon field 2) must be the
    literal "x", so the real hash lives in /etc/shadow.
    """
    for fields in _passwd_fields(facts.passwd_text):
        if fields[1] != "x":
            return False
    return True


def _evidence_passwd_accounts_use_shadowed_passwords(facts: SystemFacts) -> str:
    not_shadowed = [f[0] for f in _passwd_fields(facts.passwd_text) if f[1] != "x"]
    if not_shadowed:
        return f"/etc/passwd: not using shadowed passwords: {', '.join(not_shadowed)}"
    return "/etc/passwd: all accounts use shadowed passwords"


_GID0_EXCLUDED_PREFIXES = ("sync", "shutdown", "halt", "operator")


def _evaluate_root_only_gid0_account(facts: SystemFacts) -> bool:
    """No account other than root (ignoring sync/shutdown/halt/operator) may have
    primary GID 0 in /etc/passwd.
    """
    gid0_accounts = [
        fields[0]
        for fields in _passwd_fields(facts.passwd_text)
        if not fields[0].startswith(_GID0_EXCLUDED_PREFIXES) and fields[3] == "0"
    ]
    return gid0_accounts == ["root"]


def _evidence_root_only_gid0_account(facts: SystemFacts) -> str:
    gid0_accounts = [
        fields[0]
        for fields in _passwd_fields(facts.passwd_text)
        if not fields[0].startswith(_GID0_EXCLUDED_PREFIXES) and fields[3] == "0"
    ]
    return f"/etc/passwd: (non-excluded) accounts with primary GID 0: {', '.join(gid0_accounts) or '<none>'}"


def _evaluate_root_only_uid0_account(facts: SystemFacts) -> bool:
    """No account other than root may have UID 0."""
    uid0_accounts = [fields[0] for fields in _passwd_fields(facts.passwd_text) if fields[2] == "0"]
    return uid0_accounts == ["root"]


def _evidence_root_only_uid0_account(facts: SystemFacts) -> str:
    uid0_accounts = [fields[0] for fields in _passwd_fields(facts.passwd_text) if fields[2] == "0"]
    return f"/etc/passwd: UID 0 accounts: {', '.join(uid0_accounts) or '<none>'}"


def _group_fields(group_text: str) -> list[list[str]]:
    rows = []
    for line in group_text.splitlines():
        if not line.strip():
            continue
        fields = line.split(":")
        if len(fields) < 3:
            continue
        rows.append(fields)
    return rows


def _gid_to_group_name(group_text: str) -> dict[str, str]:
    return {fields[2]: fields[0] for fields in _group_fields(group_text)}


def _local_interactive_users(facts: SystemFacts) -> list[dict[str, str]]:
    """A "local interactive user" is any /etc/passwd account whose login shell
    (last colon field) is listed in /etc/shells and isn't a nologin-style shell.
    There is no UID_MIN cutoff, and root is not excluded: its shell is listed in
    /etc/shells, so its home directory is in scope too. Reuses
    `_valid_login_shells()`.
    """
    valid_shells = _valid_login_shells(facts)
    users = []
    for fields in _passwd_fields(facts.passwd_text):
        if len(fields) < 7:
            continue
        user, gid, home, shell = fields[0], fields[3], fields[5], fields[6]
        if shell in valid_shells:
            users.append({"user": user, "gid": gid, "home": home})
    return users


def _parse_interactive_user_files(
    text: str,
) -> tuple[dict[str, tuple[str, str, int, str]], dict[str, list[tuple[str, str, int, str]]]]:
    """Parses facts.interactive_user_files_text's `HOME`/`DOT` lines (see
    facts._INTERACTIVE_USER_FILES_CMD) into (owner, group, mode, path/name)
    tuples, keyed by username. A user with no HOME line means their home
    directory doesn't exist (the collection script only emits one when
    `[ -d "$h" ]` is true) -- not a parse failure.
    """
    homes: dict[str, tuple[str, str, int, str]] = {}
    dotfiles: dict[str, list[tuple[str, str, int, str]]] = {}
    for line in text.splitlines():
        parts = line.split(maxsplit=5)
        if len(parts) < 6:
            continue
        tag, user, owner, group, mode, rest = parts
        try:
            mode_int = int(mode, 8)
        except ValueError:
            continue
        if tag == "HOME":
            homes[user] = (owner, group, mode_int, rest)
        elif tag == "DOT":
            dotfiles.setdefault(user, []).append((owner, group, mode_int, rest))
    return homes, dotfiles


# Mask 0027: flags group-write or any other-permission bit (mode 750 or
# stricter passes).
_HOME_DIR_MASK = 0o027


def _home_dir_violations(facts: SystemFacts) -> list[str]:
    homes, _ = _parse_interactive_user_files(facts.interactive_user_files_text)
    violations = []
    for entry in _local_interactive_users(facts):
        user, home = entry["user"], entry["home"]
        info = homes.get(user)
        if info is None:
            violations.append(f"{user}: home {home} does not exist")
            continue
        owner, _group, mode, path = info
        if owner != user:
            violations.append(f"{user}: home {path} owned by {owner}")
        if mode & _HOME_DIR_MASK:
            violations.append(f"{user}: home {path} mode {oct(mode)} is not 750 or more restrictive")
    return violations


def _evaluate_interactive_user_home_dirs(facts: SystemFacts) -> bool:
    """For every local interactive user, the /etc/passwd home directory must
    exist, be owned by that user, and be mode 750 or more restrictive.
    """
    return not _home_dir_violations(facts)


def _evidence_interactive_user_home_dirs(facts: SystemFacts) -> str:
    violations = _home_dir_violations(facts)
    if violations:
        return "local interactive user home directories: " + "; ".join(violations)
    return "local interactive user home directories: all exist, owned by the user, mode 750 or more restrictive"


# Mask 0133 for ordinary dotfiles: flags group/other write or execute (mode
# 644 or stricter passes). .forward/.rhost/.netrc are excluded from this
# generic bucket; the special-case handling for them is not modeled here, so
# only the generic mode/owner/group rule below is enforced.
_DOTFILE_MASK = 0o133
_DOTFILE_EXCLUDED_NAMES = {".forward", ".rhost", ".netrc"}


def _dotfile_violations(facts: SystemFacts) -> list[str]:
    _, dotfiles = _parse_interactive_user_files(facts.interactive_user_files_text)
    gid_to_group = _gid_to_group_name(facts.group_text)
    violations = []
    for entry in _local_interactive_users(facts):
        user, home = entry["user"], entry["home"]
        primary_group = gid_to_group.get(entry["gid"])
        for owner, group, mode, name in dotfiles.get(user, []):
            if name in _DOTFILE_EXCLUDED_NAMES:
                continue
            if mode & _DOTFILE_MASK:
                violations.append(f"{user}: {home}/{name} mode {oct(mode)} is not 644 or more restrictive")
            if owner != user:
                violations.append(f"{user}: {home}/{name} owned by {owner}")
            if primary_group is not None and group != primary_group:
                violations.append(f"{user}: {home}/{name} group-owned by {group}, expected {primary_group}")
    return violations


def _evaluate_interactive_user_dotfiles(facts: SystemFacts) -> bool:
    """Every dotfile directly inside a local interactive user's home directory
    (excluding .forward/.rhost/.netrc, see _DOTFILE_EXCLUDED_NAMES) must be mode
    644 or more restrictive, owned by that user, and group-owned by their
    primary group.
    """
    return not _dotfile_violations(facts)


def _evidence_interactive_user_dotfiles(facts: SystemFacts) -> str:
    violations = _dotfile_violations(facts)
    if violations:
        return "local interactive user dot files: " + "; ".join(violations)
    return (
        "local interactive user dot files: all mode 644 or more restrictive, "
        "owned by the user and their primary group (excluding .forward/.rhost/.netrc)"
    )


def _evaluate_root_only_gid0_group(facts: SystemFacts) -> bool:
    """No group other than root may have GID 0 in /etc/group."""
    gid0_groups = [fields[0] for fields in _group_fields(facts.group_text) if fields[2] == "0"]
    return gid0_groups == ["root"]


def _evidence_root_only_gid0_group(facts: SystemFacts) -> str:
    gid0_groups = [fields[0] for fields in _group_fields(facts.group_text) if fields[2] == "0"]
    return f"/etc/group: GID 0 assigned to: {', '.join(gid0_groups) or '<none>'}"


def _evaluate_pam_faillock_enabled(facts: SystemFacts) -> bool:
    """pam_faillock.so must appear in BOTH common-auth and common-account: the
    auth hook counts/denies attempts and the account hook enforces the lockout.
    """
    return "pam_faillock.so" in facts.pam_common_auth and "pam_faillock.so" in facts.pam_common_account


def _evidence_pam_faillock_enabled(facts: SystemFacts) -> str:
    auth = "present" if "pam_faillock.so" in facts.pam_common_auth else "missing"
    account = "present" if "pam_faillock.so" in facts.pam_common_account else "missing"
    return f"pam_faillock.so: common-auth={auth}, common-account={account}"


def _evaluate_pam_pwquality_enabled(facts: SystemFacts) -> bool:
    """pam_pwquality.so must appear in /etc/pam.d/common-password."""
    return "pam_pwquality.so" in facts.pam_common_password


def _evidence_pam_pwquality_enabled(facts: SystemFacts) -> str:
    present = "present" if "pam_pwquality.so" in facts.pam_common_password else "missing"
    return f"pam_pwquality.so in common-password: {present}"


def _evaluate_pam_pwhistory_enabled(facts: SystemFacts) -> bool:
    """pam_pwhistory.so must appear in /etc/pam.d/common-password."""
    return "pam_pwhistory.so" in facts.pam_common_password


def _evidence_pam_pwhistory_enabled(facts: SystemFacts) -> str:
    present = "present" if "pam_pwhistory.so" in facts.pam_common_password else "missing"
    return f"pam_pwhistory.so in common-password: {present}"


def _pam_unix_nullok_lines(facts: SystemFacts) -> list[str]:
    """Lines across common-auth/common-password/common-account that configure
    pam_unix.so with the nullok argument, which lets an account with an empty
    password authenticate. common-session and common-session-noninteractive are
    not collected by facts.SystemFacts, so they are not inspected.
    """
    offending = []
    for text in (facts.pam_common_auth, facts.pam_common_password, facts.pam_common_account):
        for line in text.splitlines():
            if "pam_unix.so" in line and "nullok" in line:
                offending.append(line.strip())
    return offending


def _evaluate_pam_no_nullok(facts: SystemFacts) -> bool:
    return len(_pam_unix_nullok_lines(facts)) == 0


def _evidence_pam_no_nullok(facts: SystemFacts) -> str:
    lines = _pam_unix_nullok_lines(facts)
    if not lines:
        return "no nullok found on pam_unix.so lines in common-auth/common-password/common-account"
    return "nullok found: " + " | ".join(lines)


# Group G: password quality/history, via pwquality.conf and pwhistory.conf.
def parse_pwquality_conf(text: str) -> dict[str, str]:
    """Parses "key = value" lines from pwquality.conf/pwhistory.conf -- both
    files share this exact format (comments/blank lines skipped, later lines
    win, same convention as parse_login_defs()). Boolean-style options like
    enforce_for_root appear on their own line with no "=" at all; those map
    to "" so a plain membership check (`"enforce_for_root" in directives`)
    is enough to detect them.
    """
    directives = {}
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        key, sep, value = stripped.partition("=")
        directives[key.strip().lower()] = value.strip() if sep else ""
    return directives


def _evaluate_pwquality_enforce_for_root(facts: SystemFacts) -> bool:
    """`enforce_for_root` must be present in pwquality.conf (or its .d drop-ins).
    Presence of the bare flag is what's checked, not a value.
    """
    return "enforce_for_root" in parse_pwquality_conf(facts.pwquality_text)


def _evidence_pwquality_enforce_for_root(facts: SystemFacts) -> str:
    present = "present" if "enforce_for_root" in parse_pwquality_conf(facts.pwquality_text) else "missing"
    return f"pwquality.conf: enforce_for_root {present}"


def _evaluate_pwquality_minlen(facts: SystemFacts) -> bool:
    """minlen must be set in pwquality.conf and be >= 14."""
    value = parse_pwquality_conf(facts.pwquality_text).get("minlen")
    if value is None:
        return False
    try:
        return int(value) >= 14
    except ValueError:
        return False


def _evidence_pwquality_minlen(facts: SystemFacts) -> str:
    value = parse_pwquality_conf(facts.pwquality_text).get("minlen", "<not set>")
    return f"pwquality.conf: minlen {value}"


# No single documented threshold exists for complexity, so this evaluator
# adopts one: either minclass requires at least 3 character classes, or at
# least 3 of the 4 [dulo]credit knobs are set to mandatory (negative) with
# none left positive (positive relaxes, rather than tightens, pam_pwquality's
# default policy).
_PWQUALITY_CREDIT_KEYS = ("dcredit", "ucredit", "lcredit", "ocredit")


def _evaluate_pwquality_complexity(facts: SystemFacts) -> bool:
    directives = parse_pwquality_conf(facts.pwquality_text)

    minclass = directives.get("minclass")
    if minclass is not None:
        try:
            if int(minclass) >= 3:
                return True
        except ValueError:
            pass

    credit_values = []
    for key in _PWQUALITY_CREDIT_KEYS:
        value = directives.get(key)
        if value is None:
            continue
        try:
            credit_values.append(int(value))
        except ValueError:
            continue
    negative = sum(1 for v in credit_values if v < 0)
    positive = any(v > 0 for v in credit_values)
    return negative >= 3 and not positive


def _evidence_pwquality_complexity(facts: SystemFacts) -> str:
    directives = parse_pwquality_conf(facts.pwquality_text)
    parts = [f"{key}={directives[key]}" for key in ("minclass", *_PWQUALITY_CREDIT_KEYS) if key in directives]
    if not parts:
        return "pwquality.conf: none of minclass/dcredit/ucredit/lcredit/ocredit set"
    return "pwquality.conf: " + ", ".join(parts)


def _evaluate_pwquality_max_repeat(facts: SystemFacts) -> bool:
    """maxrepeat must be set, 3 or less, and not 0 (0 disables the check per
    pwquality.conf's own documentation).
    """
    value = parse_pwquality_conf(facts.pwquality_text).get("maxrepeat")
    if value is None:
        return False
    try:
        n = int(value)
    except ValueError:
        return False
    return 1 <= n <= 3


def _evidence_pwquality_max_repeat(facts: SystemFacts) -> str:
    value = parse_pwquality_conf(facts.pwquality_text).get("maxrepeat", "<not set>")
    return f"pwquality.conf: maxrepeat {value}"


def _evaluate_pwquality_max_sequence(facts: SystemFacts) -> bool:
    """maxsequence must be set, 3 or less, and not 0 -- same shape as maxrepeat."""
    value = parse_pwquality_conf(facts.pwquality_text).get("maxsequence")
    if value is None:
        return False
    try:
        n = int(value)
    except ValueError:
        return False
    return 1 <= n <= 3


def _evidence_pwquality_max_sequence(facts: SystemFacts) -> str:
    value = parse_pwquality_conf(facts.pwquality_text).get("maxsequence", "<not set>")
    return f"pwquality.conf: maxsequence {value}"


def _evaluate_pwquality_difok(facts: SystemFacts) -> bool:
    """difok must be set and >= 2."""
    value = parse_pwquality_conf(facts.pwquality_text).get("difok")
    if value is None:
        return False
    try:
        return int(value) >= 2
    except ValueError:
        return False


def _evidence_pwquality_difok(facts: SystemFacts) -> str:
    value = parse_pwquality_conf(facts.pwquality_text).get("difok", "<not set>")
    return f"pwquality.conf: difok {value}"


def _pam_pwhistory_line(facts: SystemFacts) -> str:
    """The common-password line configuring pam_pwhistory.so, if any --
    shared by both password-history evaluators below.
    """
    for line in facts.pam_common_password.splitlines():
        if "pam_pwhistory.so" in line:
            return line.strip()
    return ""


def _pam_pwhistory_remember(facts: SystemFacts) -> int | None:
    match = re.search(r"remember=(\d+)", _pam_pwhistory_line(facts))
    return int(match.group(1)) if match else None


def _evaluate_pwhistory_remember(facts: SystemFacts) -> bool:
    """remember must be >= 24. It is read from the pam_pwhistory.so `remember=<N>`
    argument on common-password's pwhistory line, or from /etc/security/
    pwhistory.conf's own `remember=` directive; either one meeting the
    threshold passes.
    """
    conf_value = parse_pwquality_conf(facts.pwhistory_text).get("remember")
    if conf_value is not None:
        try:
            if int(conf_value) >= 24:
                return True
        except ValueError:
            pass
    remember = _pam_pwhistory_remember(facts)
    return remember is not None and remember >= 24


def _evidence_pwhistory_remember(facts: SystemFacts) -> str:
    conf_value = parse_pwquality_conf(facts.pwhistory_text).get("remember", "<not set>")
    remember = _pam_pwhistory_remember(facts)
    pam_value = str(remember) if remember is not None else "<not set>"
    return f"pwhistory.conf: remember {conf_value}; common-password pam_pwhistory.so: remember {pam_value}"


def _evaluate_pwhistory_enforce_for_root(facts: SystemFacts) -> bool:
    """Same two-location split as _evaluate_pwhistory_remember(): the root
    enforcement flag may sit in pwhistory.conf or on the pam_pwhistory.so line.
    """
    if "enforce_for_root" in parse_pwquality_conf(facts.pwhistory_text):
        return True
    return "enforce_for_root" in _pam_pwhistory_line(facts)


def _evidence_pwhistory_enforce_for_root(facts: SystemFacts) -> str:
    conf_present = "present" if "enforce_for_root" in parse_pwquality_conf(facts.pwhistory_text) else "missing"
    pam_present = "present" if "enforce_for_root" in _pam_pwhistory_line(facts) else "missing"
    return f"pwhistory.conf: enforce_for_root {conf_present}; common-password pam_pwhistory.so: enforce_for_root {pam_present}"


# Group H: pam_faillock lockout policy, via faillock.conf + pam_faillock.so's
# own inline arguments on /etc/pam.d/common-auth. Each check has the same
# two-part shape as pwhistory_remember above: a faillock.conf directive, AND
# (if pam_faillock.so also sets the same argument inline on common-auth) that
# inline value must independently not fall in a disallowed range.
_FAILLOCK_UNLOCK_TIME_BAD_RE = re.compile(r"(?<!root_)unlock_time\s*=\s*([1-9]|[1-9][0-9]|[1-8][0-9]{2})\b")
_FAILLOCK_DENY_BAD_RE = re.compile(r"deny\s*=\s*(0|[6-9]|[1-9][0-9]+)\b")
_FAILLOCK_ROOT_UNLOCK_TIME_BAD_RE = re.compile(r"root_unlock_time\s*=\s*([1-9]|[1-5][0-9])\b")


def _pam_faillock_lines(facts: SystemFacts) -> list[str]:
    """Lines in common-auth configuring pam_faillock.so -- typically 2-3
    (preauth/authfail/authsucc), any of which may carry its own inline
    deny=/unlock_time=/root_unlock_time= argument overriding faillock.conf.
    """
    return [line.strip() for line in facts.pam_common_auth.splitlines() if "pam_faillock.so" in line]


def _evaluate_faillock_unlock_time(facts: SystemFacts) -> bool:
    """faillock.conf's unlock_time must be 0 (never) or >= 900 (15 minutes) if set
    at all -- absent is acceptable. AND, if pam_faillock.so's own unlock_time=
    argument is set inline on common-auth, it must not fall in the disallowed
    1-899 range either.
    """
    value = parse_pwquality_conf(facts.faillock_text).get("unlock_time")
    if value is not None:
        try:
            n = int(value)
        except ValueError:
            return False
        if not (n == 0 or n >= 900):
            return False
    return not any(_FAILLOCK_UNLOCK_TIME_BAD_RE.search(line) for line in _pam_faillock_lines(facts))


def _evidence_faillock_unlock_time(facts: SystemFacts) -> str:
    value = parse_pwquality_conf(facts.faillock_text).get("unlock_time", "<not set>")
    pam_lines = "; ".join(_pam_faillock_lines(facts)) or "<no pam_faillock.so line>"
    return f"faillock.conf: unlock_time {value}; common-auth pam_faillock.so: {pam_lines}"


def _evaluate_faillock_deny(facts: SystemFacts) -> bool:
    """faillock.conf's deny must be in 1-5 if set at all (absent is acceptable,
    same precedent as the pwquality/pwhistory checks above). AND
    pam_faillock.so's own inline deny= argument, if set, must not be 0 or >= 6.
    """
    value = parse_pwquality_conf(facts.faillock_text).get("deny")
    if value is not None:
        try:
            n = int(value)
        except ValueError:
            return False
        if not (1 <= n <= 5):
            return False
    return not any(_FAILLOCK_DENY_BAD_RE.search(line) for line in _pam_faillock_lines(facts))


def _evidence_faillock_deny(facts: SystemFacts) -> str:
    value = parse_pwquality_conf(facts.faillock_text).get("deny", "<not set>")
    pam_lines = "; ".join(_pam_faillock_lines(facts)) or "<no pam_faillock.so line>"
    return f"faillock.conf: deny {value}; common-auth pam_faillock.so: {pam_lines}"


def _evaluate_faillock_root_lockout(facts: SystemFacts) -> bool:
    """faillock.conf must set even_deny_root and/or root_unlock_time. If
    root_unlock_time is set, it must be 0 or >= 60 (disallowed range 1-59).
    Same secondary check as the other two: if pam_faillock.so's own
    root_unlock_time= argument is set inline on common-auth, it must not fall in
    that disallowed range either.
    """
    directives = parse_pwquality_conf(facts.faillock_text)
    if "even_deny_root" not in directives and "root_unlock_time" not in directives:
        return False
    root_unlock_time = directives.get("root_unlock_time")
    if root_unlock_time is not None:
        try:
            n = int(root_unlock_time)
        except ValueError:
            return False
        if not (n == 0 or n >= 60):
            return False
    return not any(_FAILLOCK_ROOT_UNLOCK_TIME_BAD_RE.search(line) for line in _pam_faillock_lines(facts))


def _evidence_faillock_root_lockout(facts: SystemFacts) -> str:
    directives = parse_pwquality_conf(facts.faillock_text)
    even_deny_root = "present" if "even_deny_root" in directives else "missing"
    root_unlock_time = directives.get("root_unlock_time", "<not set>")
    pam_lines = "; ".join(_pam_faillock_lines(facts)) or "<no pam_faillock.so line>"
    return (
        f"faillock.conf: even_deny_root {even_deny_root}, root_unlock_time {root_unlock_time}; "
        f"common-auth pam_faillock.so: {pam_lines}"
    )


def parse_login_defs(text: str) -> dict[str, str]:
    """Parses "KEY value" lines from /etc/login.defs -- same shape as
    parse_sshd_config() in facts.py (comments/blank lines skipped, later
    lines win), just uppercase keys since that's login.defs' own
    convention (UMASK, ENCRYPT_METHOD, PASS_MAX_DAYS, ...).
    """
    directives = {}
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        parts = stripped.split(None, 1)
        if len(parts) != 2:
            continue
        key, value = parts
        directives[key.upper()] = value.strip()
    return directives


def _evaluate_default_umask(facts: SystemFacts) -> bool:
    """UMASK in /etc/login.defs must be 027 or more restrictive. "More
    restrictive" means at least those bits are masked -- `umask & 0o027 ==
    0o027` accepts 027 itself and anything stricter (037, 077, ...) without
    hardcoding a single allowed value.
    """
    value = parse_login_defs(facts.login_defs_text).get("UMASK")
    if value is None:
        return False
    try:
        umask = int(value, 8)
    except ValueError:
        return False
    return (umask & 0o027) == 0o027


def _evidence_default_umask(facts: SystemFacts) -> str:
    value = parse_login_defs(facts.login_defs_text).get("UMASK", "<not set>")
    return f"login.defs: UMASK {value}"


def _evaluate_ssh_max_sessions(facts: SystemFacts) -> bool:
    value = facts.sshd_config.get("maxsessions", "")
    try:
        return int(value) <= 10
    except ValueError:
        return False


def _evidence_ssh_max_sessions(facts: SystemFacts) -> str:
    value = _sshd_directive_value(facts, "maxsessions")
    return f"sshd_config: MaxSessions {value}"


def _evaluate_ssh_log_level(facts: SystemFacts) -> bool:
    """LogLevel must be VERBOSE or INFO (both accepted, not just INFO)."""
    return facts.sshd_config.get("loglevel", "").lower() in ("info", "verbose")


def _evidence_ssh_log_level(facts: SystemFacts) -> str:
    value = _sshd_directive_value(facts, "loglevel")
    return f"sshd_config: LogLevel {value}"


def _evaluate_ssh_use_pam(facts: SystemFacts) -> bool:
    return facts.sshd_config.get("usepam", "").lower() == "yes"


def _evidence_ssh_use_pam(facts: SystemFacts) -> str:
    value = _sshd_directive_value(facts, "usepam")
    return f"sshd_config: UsePAM {value}"


def _evaluate_ssh_disable_forwarding(facts: SystemFacts) -> bool:
    """Checks the single DisableForwarding directive (OpenSSH 8.7+), which
    disables all forwarding types at once, rather than the per-directive
    AllowTcpForwarding/AllowAgentForwarding settings.
    """
    return facts.sshd_config.get("disableforwarding", "").lower() == "yes"


def _evidence_ssh_disable_forwarding(facts: SystemFacts) -> str:
    value = _sshd_directive_value(facts, "disableforwarding")
    return f"sshd_config: DisableForwarding {value}"


# Ciphers treated as weak: cbc-mode 3des/blowfish/cast128/aes, arcfour
# variants, an old rijndael-cbc alias, and chacha20-poly1305@openssh.com
# (flagged for CVE-2023-48795, the Terrapin attack, unless patched -- treated
# as weak unconditionally here since a patch level isn't something facts.py
# collects).
_WEAK_CIPHER_RE = re.compile(
    r"^(3des|blowfish|cast128|aes(128|192|256))-cbc$"
    r"|^arcfour(128|256)?$"
    r"|^rijndael-cbc@lysator\.liu\.se$"
    r"|^chacha20-poly1305@openssh\.com$"
)


def _evaluate_ssh_ciphers(facts: SystemFacts) -> bool:
    ciphers = facts.sshd_config.get("ciphers", "")
    if not ciphers:
        return False
    return not any(_WEAK_CIPHER_RE.match(c.strip().lower()) for c in ciphers.split(","))


def _evidence_ssh_ciphers(facts: SystemFacts) -> str:
    value = _sshd_directive_value(facts, "ciphers")
    return f"sshd_config: Ciphers {value}"


# Key exchange algorithms treated as weak. This is a plain weak-algorithm
# denylist, not a FIPS-validated allowlist.
_WEAK_KEX_ALGORITHMS = {
    "diffie-hellman-group1-sha1",
    "diffie-hellman-group14-sha1",
    "diffie-hellman-group-exchange-sha1",
}


def _evaluate_ssh_kex_algorithms(facts: SystemFacts) -> bool:
    kex = facts.sshd_config.get("kexalgorithms", "")
    if not kex:
        return False
    algorithms = {a.strip().lower() for a in kex.split(",")}
    return not (algorithms & _WEAK_KEX_ALGORITHMS)


def _evidence_ssh_kex_algorithms(facts: SystemFacts) -> str:
    value = _sshd_directive_value(facts, "kexalgorithms")
    return f"sshd_config: KexAlgorithms {value}"


_PRIVATE_HOST_KEY_PATHS = [
    "/etc/ssh/ssh_host_rsa_key",
    "/etc/ssh/ssh_host_ecdsa_key",
    "/etc/ssh/ssh_host_ed25519_key",
]

_PUBLIC_HOST_KEY_PATHS = [
    "/etc/ssh/ssh_host_rsa_key.pub",
    "/etc/ssh/ssh_host_ecdsa_key.pub",
    "/etc/ssh/ssh_host_ed25519_key.pub",
]


def _evaluate_ssh_private_host_key_permissions(facts: SystemFacts) -> bool:
    """Mode 0600 or more restrictive, owned by root, for each private host key
    file that exists -- a simplified rule that does not accept a group-owned
    0640 for a dedicated ssh key group. A target with no host key files present
    passes, since that's a "nothing to secure" state, not a misconfiguration.
    """
    present = [facts.file_stats[p] for p in _PRIVATE_HOST_KEY_PATHS if facts.file_stats.get(p) and facts.file_stats[p].mode is not None]
    if not present:
        return True
    return all(stat.mode <= 0o600 and stat.uid == 0 for stat in present)


def _evidence_ssh_private_host_key_permissions(facts: SystemFacts) -> str:
    parts = [
        f"{path}: mode={oct(stat.mode)} uid={stat.uid}"
        for path in _PRIVATE_HOST_KEY_PATHS
        if (stat := facts.file_stats.get(path)) and stat.mode is not None
    ]
    return "; ".join(parts) if parts else "no SSH private host key files found"


def _evaluate_ssh_public_host_key_permissions(facts: SystemFacts) -> bool:
    """Mode 0644 or more restrictive, owned by root:root, for each public host
    key file that exists. Same "nothing to secure" PASS as the private key
    check when no host key files are present.
    """
    present = [facts.file_stats[p] for p in _PUBLIC_HOST_KEY_PATHS if facts.file_stats.get(p) and facts.file_stats[p].mode is not None]
    if not present:
        return True
    return all(stat.mode <= 0o644 and stat.uid == 0 and stat.gname == "root" for stat in present)


def _evidence_ssh_public_host_key_permissions(facts: SystemFacts) -> str:
    parts = [
        f"{path}: mode={oct(stat.mode)} uid={stat.uid} gid={stat.gid}({stat.gname})"
        for path in _PUBLIC_HOST_KEY_PATHS
        if (stat := facts.file_stats.get(path)) and stat.mode is not None
    ]
    return "; ".join(parts) if parts else "no SSH public host key files found"


def _packages_absent(facts: SystemFacts, *names: str) -> bool:
    """True if none of `names` are in the collected package set -- the shared
    shape behind every "package X is not installed" check below. Some packages
    are renamed across releases (e.g. "telnet" vs "inetutils-telnet"); passing
    every known name and requiring all of them absent is a safe superset of a
    single-name check, since on a genuinely clean system every name in the set
    is absent anyway.
    """
    return not any(name in facts.installed_packages for name in names)


def _evaluate_ldap_client_not_installed(facts: SystemFacts) -> bool:
    return _packages_absent(facts, "ldap-utils")


def _evidence_ldap_client_not_installed(facts: SystemFacts) -> str:
    present = "ldap-utils" in facts.installed_packages
    return f"installed_packages: ldap-utils {'present' if present else 'absent'}"


def _evaluate_nis_client_not_installed(facts: SystemFacts) -> bool:
    return _packages_absent(facts, "nis")


def _evidence_nis_client_not_installed(facts: SystemFacts) -> str:
    present = "nis" in facts.installed_packages
    return f"installed_packages: nis {'present' if present else 'absent'}"


def _evaluate_xinetd_not_installed(facts: SystemFacts) -> bool:
    return _packages_absent(facts, "xinetd")


def _evidence_xinetd_not_installed(facts: SystemFacts) -> str:
    present = "xinetd" in facts.installed_packages
    return f"installed_packages: xinetd {'present' if present else 'absent'}"


def _evaluate_rsync_not_installed(facts: SystemFacts) -> bool:
    return _packages_absent(facts, "rsync")


def _evidence_rsync_not_installed(facts: SystemFacts) -> str:
    present = "rsync" in facts.installed_packages
    return f"installed_packages: rsync {'present' if present else 'absent'}"


def _evaluate_x_window_not_installed(facts: SystemFacts) -> bool:
    return _packages_absent(facts, "xserver-common")


def _evidence_x_window_not_installed(facts: SystemFacts) -> str:
    present = "xserver-common" in facts.installed_packages
    return f"installed_packages: xserver-common {'present' if present else 'absent'}"


def _evaluate_telnet_client_not_installed(facts: SystemFacts) -> bool:
    return _packages_absent(facts, "telnet", "inetutils-telnet")


def _evidence_telnet_client_not_installed(facts: SystemFacts) -> str:
    present = [p for p in ("telnet", "inetutils-telnet") if p in facts.installed_packages]
    return f"installed_packages: telnet/inetutils-telnet {'present: ' + ','.join(present) if present else 'absent'}"


def _evaluate_rsh_client_not_installed(facts: SystemFacts) -> bool:
    return _packages_absent(facts, "rsh-client")


def _evidence_rsh_client_not_installed(facts: SystemFacts) -> str:
    present = "rsh-client" in facts.installed_packages
    return f"installed_packages: rsh-client {'present' if present else 'absent'}"


def _evaluate_ftp_client_not_installed(facts: SystemFacts) -> bool:
    return _packages_absent(facts, "ftp", "tnftp")


def _evidence_ftp_client_not_installed(facts: SystemFacts) -> str:
    present = [p for p in ("ftp", "tnftp") if p in facts.installed_packages]
    return f"installed_packages: ftp/tnftp {'present: ' + ','.join(present) if present else 'absent'}"


def _evaluate_talk_client_not_installed(facts: SystemFacts) -> bool:
    return _packages_absent(facts, "talk")


def _evidence_talk_client_not_installed(facts: SystemFacts) -> str:
    present = "talk" in facts.installed_packages
    return f"installed_packages: talk {'present' if present else 'absent'}"


def _evaluate_prelink_not_installed(facts: SystemFacts) -> bool:
    return _packages_absent(facts, "prelink")


def _evidence_prelink_not_installed(facts: SystemFacts) -> str:
    present = "prelink" in facts.installed_packages
    return f"installed_packages: prelink {'present' if present else 'absent'}"


# Group K: package presence -- the opposite direction of the "not installed"
# checks above, same installed_packages field (ufw).
def _evaluate_ufw_installed(facts: SystemFacts) -> bool:
    return "ufw" in facts.installed_packages


def _evidence_ufw_installed(facts: SystemFacts) -> str:
    present = "ufw" in facts.installed_packages
    return f"installed_packages: ufw {'present' if present else 'absent'}"


# Group M: unused network service packages, batch A. Same "package must NOT
# be installed" shape as the client-side checks above, just server-side
# daemons. Any "installed but disabled" exemption is not modeled, since
# facts.py doesn't collect systemd unit state: only the package-installed
# condition is evaluated here, like every other package-absent check in this
# file.
def _evaluate_avahi_not_installed(facts: SystemFacts) -> bool:
    return _packages_absent(facts, "avahi-daemon")


def _evidence_avahi_not_installed(facts: SystemFacts) -> str:
    present = "avahi-daemon" in facts.installed_packages
    return f"installed_packages: avahi-daemon {'present' if present else 'absent'}"


def _evaluate_bluetooth_not_installed(facts: SystemFacts) -> bool:
    return _packages_absent(facts, "bluez")


def _evidence_bluetooth_not_installed(facts: SystemFacts) -> str:
    present = "bluez" in facts.installed_packages
    return f"installed_packages: bluez {'present' if present else 'absent'}"


# isc-dhcp-server was replaced by kea in newer releases (same split as
# telnet/inetutils-telnet above). Both must be absent to PASS.
def _evaluate_dhcp_server_not_installed(facts: SystemFacts) -> bool:
    return _packages_absent(facts, "isc-dhcp-server", "kea")


def _evidence_dhcp_server_not_installed(facts: SystemFacts) -> str:
    present = [p for p in ("isc-dhcp-server", "kea") if p in facts.installed_packages]
    return f"installed_packages: isc-dhcp-server/kea {'present: ' + ','.join(present) if present else 'absent'}"


def _evaluate_dns_server_not_installed(facts: SystemFacts) -> bool:
    return _packages_absent(facts, "bind9")


def _evidence_dns_server_not_installed(facts: SystemFacts) -> str:
    present = "bind9" in facts.installed_packages
    return f"installed_packages: bind9 {'present' if present else 'absent'}"


def _evaluate_dnsmasq_not_installed(facts: SystemFacts) -> bool:
    return _packages_absent(facts, "dnsmasq")


def _evidence_dnsmasq_not_installed(facts: SystemFacts) -> str:
    present = "dnsmasq" in facts.installed_packages
    return f"installed_packages: dnsmasq {'present' if present else 'absent'}"


# One of the supported documents describes this check with an FTP *client*
# package list instead of vsftpd, which is treated as a documentation
# artifact; vsftpd is checked uniformly on every target.
def _evaluate_ftp_server_not_installed(facts: SystemFacts) -> bool:
    return _packages_absent(facts, "vsftpd")


def _evidence_ftp_server_not_installed(facts: SystemFacts) -> str:
    present = "vsftpd" in facts.installed_packages
    return f"installed_packages: vsftpd {'present' if present else 'absent'}"


def _evaluate_ldap_server_not_installed(facts: SystemFacts) -> bool:
    return _packages_absent(facts, "slapd")


def _evidence_ldap_server_not_installed(facts: SystemFacts) -> str:
    present = "slapd" in facts.installed_packages
    return f"installed_packages: slapd {'present' if present else 'absent'}"


# Two distinct packages (IMAP and POP3 servers), not name-drift aliases
# like isc-dhcp-server/kea above: either one present is a finding, so both
# must be absent to PASS.
def _evaluate_message_access_server_not_installed(facts: SystemFacts) -> bool:
    return _packages_absent(facts, "dovecot-imapd", "dovecot-pop3d")


def _evidence_message_access_server_not_installed(facts: SystemFacts) -> str:
    present = [p for p in ("dovecot-imapd", "dovecot-pop3d") if p in facts.installed_packages]
    return f"installed_packages: dovecot-imapd/dovecot-pop3d {'present: ' + ','.join(present) if present else 'absent'}"


def _evaluate_nfs_server_not_installed(facts: SystemFacts) -> bool:
    return _packages_absent(facts, "nfs-kernel-server")


def _evidence_nfs_server_not_installed(facts: SystemFacts) -> str:
    present = "nfs-kernel-server" in facts.installed_packages
    return f"installed_packages: nfs-kernel-server {'present' if present else 'absent'}"


def _evaluate_nis_server_not_installed(facts: SystemFacts) -> bool:
    return _packages_absent(facts, "ypserv")


def _evidence_nis_server_not_installed(facts: SystemFacts) -> str:
    present = "ypserv" in facts.installed_packages
    return f"installed_packages: ypserv {'present' if present else 'absent'}"


# Group I: auditd config/tooling file ownership + rules immutability. The
# file sets are wider than what facts._STAT_PATHS collects (no
# /etc/audit/auditd.conf, no /sbin/aureport, /sbin/ausearch, /sbin/autrace).
# _owner_ok() below checks ownership only over the subset of each set that
# facts.py actually stats; adding the missing paths would tighten the checks.
_AUDIT_CONFIG_PATHS = ["/etc/audit/audit.rules", "/etc/audit/rules.d"]
_AUDIT_TOOL_PATHS = ["/sbin/auditctl", "/sbin/auditd", "/sbin/augenrules"]


def _owner_ok(
    facts: SystemFacts,
    paths: list[str],
    *,
    uid: int | None = None,
    gnames: tuple[str, ...] | None = None,
) -> bool:
    """Shared by the Group I audit-file ownership checks: every path in
    `paths` must be present in facts.file_stats and match the given uid
    and/or group name(s). A path that failed to stat (or wasn't collected)
    fails closed, same posture as _permissions_ok above.
    """
    for path in paths:
        stat = facts.file_stats.get(path)
        if stat is None or stat.uid is None:
            return False
        if uid is not None and stat.uid != uid:
            return False
        if gnames is not None and stat.gname not in gnames:
            return False
    return True


def _evidence_for_stats(paths: list[str]) -> Callable[[SystemFacts], str]:
    def _evidence(facts: SystemFacts) -> str:
        parts = []
        for path in paths:
            stat = facts.file_stats.get(path)
            if stat is None or stat.uid is None:
                parts.append(f"{path}: could not stat")
            else:
                parts.append(f"{path}: uid={stat.uid} gid={stat.gid}({stat.gname})")
        return " | ".join(parts)

    return _evidence


def _evaluate_audit_conf_files_owner(facts: SystemFacts) -> bool:
    return _owner_ok(facts, _AUDIT_CONFIG_PATHS, uid=0)


_evidence_audit_conf_files_owner = _evidence_for_stats(_AUDIT_CONFIG_PATHS)


def _evaluate_audit_conf_files_group_owner(facts: SystemFacts) -> bool:
    return _owner_ok(facts, _AUDIT_CONFIG_PATHS, gnames=("root",))


_evidence_audit_conf_files_group_owner = _evidence_for_stats(_AUDIT_CONFIG_PATHS)


def _evaluate_audit_tools_owner(facts: SystemFacts) -> bool:
    return _owner_ok(facts, _AUDIT_TOOL_PATHS, uid=0)


_evidence_audit_tools_owner = _evidence_for_stats(_AUDIT_TOOL_PATHS)


def _evaluate_audit_tools_group_owner(facts: SystemFacts) -> bool:
    return _owner_ok(facts, _AUDIT_TOOL_PATHS, gnames=("root",))


_evidence_audit_tools_group_owner = _evidence_for_stats(_AUDIT_TOOL_PATHS)


# The immutable flag (`-e 2`) must be present in the audit rules, so no
# further rule changes can take effect without a reboot.
# facts.audit_rules_text concatenates rules.d/*.rules then audit.rules (the
# latter is generated from the former by augenrules on a working system, so
# they agree); a simple presence check over that combined text is equivalent
# here since the pattern only ever matches an actual "-e 2" line.
_AUDIT_IMMUTABLE_RE = re.compile(r"^\s*-e\s+2\b", re.MULTILINE)


def _evaluate_audit_config_immutable(facts: SystemFacts) -> bool:
    return bool(_AUDIT_IMMUTABLE_RE.search(facts.audit_rules_text))


def _evidence_audit_config_immutable(facts: SystemFacts) -> str:
    matches = _AUDIT_IMMUTABLE_RE.findall(facts.audit_rules_text)
    if not matches:
        return "audit rules: no '-e 2' (immutable) line found"
    return f"audit rules: found {len(matches)} '-e 2' line(s)"


def _sudoers_active_lines(text: str) -> list[str]:
    """Non-blank, non-comment lines from /etc/sudoers text -- comment detection
    follows the same "strip, then check for a leading #" rule as the pam_unix
    nullok check above, so an indented "  # ..." line is not treated as active.
    """
    return [line.strip() for line in text.splitlines() if line.strip() and not line.strip().startswith("#")]


def _evaluate_sudo_no_nopasswd(facts: SystemFacts) -> bool:
    """No active sudoers line may grant NOPASSWD privilege escalation. facts.py
    only collects /etc/sudoers itself, not /etc/sudoers.d/* -- a drop-in
    NOPASSWD rule there is invisible to this check, same known gap as the
    nullok check's missing common-session files.
    """
    return not any("NOPASSWD" in line for line in _sudoers_active_lines(facts.sudoers_text))


def _evidence_sudo_no_nopasswd(facts: SystemFacts) -> str:
    offending = [line for line in _sudoers_active_lines(facts.sudoers_text) if "NOPASSWD" in line]
    if offending:
        return "sudoers: NOPASSWD found: " + " | ".join(offending)
    return "sudoers: no NOPASSWD entries"


def _evaluate_sudo_reauthentication_required(facts: SystemFacts) -> bool:
    """No active sudoers line may carry a !authenticate tag, which lets a user run
    sudo without re-entering their password at all.
    """
    return not any("!authenticate" in line for line in _sudoers_active_lines(facts.sudoers_text))


def _evidence_sudo_reauthentication_required(facts: SystemFacts) -> str:
    offending = [line for line in _sudoers_active_lines(facts.sudoers_text) if "!authenticate" in line]
    if offending:
        return "sudoers: !authenticate found: " + " | ".join(offending)
    return "sudoers: no !authenticate entries"


_SUDO_LOGFILE_RE = re.compile(r"(?i)^Defaults\b.*\blogfile\s*=\s*\S")


def _evaluate_sudo_log_file_exists(facts: SystemFacts) -> bool:
    """/etc/sudoers must contain a `Defaults ... logfile=...` line."""
    return any(_SUDO_LOGFILE_RE.match(line) for line in _sudoers_active_lines(facts.sudoers_text))


def _evidence_sudo_log_file_exists(facts: SystemFacts) -> str:
    match = next((line for line in _sudoers_active_lines(facts.sudoers_text) if _SUDO_LOGFILE_RE.match(line)), None)
    return f"sudoers: {match}" if match else "sudoers: no Defaults logfile= line found"


# Group H: cron file/directory permissions. Same shape as _permissions_ok's
# other users -- stat mode <= a ceiling, uid 0/root, gid 0/root -- with a
# 0600 ceiling for /etc/crontab and a 0700 ceiling for the five cron.*
# directories (packaged defaults are 644/755, i.e. non-compliant out of the
# box, the same gotcha as sshd_config's own file permissions).
def _evaluate_etc_crontab_permissions(facts: SystemFacts) -> bool:
    return _permissions_ok(facts, "/etc/crontab", 0o600, ("root",))


_evidence_etc_crontab_permissions = _evidence_for_stat("/etc/crontab")


def _evaluate_cron_hourly_permissions(facts: SystemFacts) -> bool:
    return _permissions_ok(facts, "/etc/cron.hourly", 0o700, ("root",))


_evidence_cron_hourly_permissions = _evidence_for_stat("/etc/cron.hourly")


def _evaluate_cron_daily_permissions(facts: SystemFacts) -> bool:
    return _permissions_ok(facts, "/etc/cron.daily", 0o700, ("root",))


_evidence_cron_daily_permissions = _evidence_for_stat("/etc/cron.daily")


def _evaluate_cron_weekly_permissions(facts: SystemFacts) -> bool:
    return _permissions_ok(facts, "/etc/cron.weekly", 0o700, ("root",))


_evidence_cron_weekly_permissions = _evidence_for_stat("/etc/cron.weekly")


def _evaluate_cron_monthly_permissions(facts: SystemFacts) -> bool:
    return _permissions_ok(facts, "/etc/cron.monthly", 0o700, ("root",))


_evidence_cron_monthly_permissions = _evidence_for_stat("/etc/cron.monthly")


def _evaluate_cron_d_permissions(facts: SystemFacts) -> bool:
    return _permissions_ok(facts, "/etc/cron.d", 0o700, ("root",))


_evidence_cron_d_permissions = _evidence_for_stat("/etc/cron.d")


def parse_journald_conf(text: str) -> dict[str, str]:
    """Parses "Key=Value" lines from /etc/systemd/journald.conf -- same
    directive-file shape as parse_sshd_config()/parse_login_defs(), just
    with a `=` separator (systemd's own config-file convention) and
    lowercased keys for case-insensitive lookup. Comment lines (#, ;),
    blank lines, and section headers like [Journal] (no `=` in them) are
    skipped; later lines win on conflict.
    """
    directives = {}
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or stripped.startswith(";"):
            continue
        if "=" not in stripped:
            continue
        key, _, value = stripped.partition("=")
        directives[key.strip().lower()] = value.strip()
    return directives


def _evaluate_journald_compress(facts: SystemFacts) -> bool:
    """journald.conf must contain `Compress=yes`."""
    return parse_journald_conf(facts.journald_text).get("compress", "").lower() == "yes"


def _evidence_journald_compress(facts: SystemFacts) -> str:
    value = parse_journald_conf(facts.journald_text).get("compress", "<not set>")
    return f"journald.conf: Compress={value}"


def _evaluate_journald_storage(facts: SystemFacts) -> bool:
    """journald.conf must contain `Storage=persistent`."""
    return parse_journald_conf(facts.journald_text).get("storage", "").lower() == "persistent"


def _evidence_journald_storage(facts: SystemFacts) -> str:
    value = parse_journald_conf(facts.journald_text).get("storage", "<not set>")
    return f"journald.conf: Storage={value}"


# Log-rotation parameters: SystemMaxUse, SystemKeepFree, RuntimeMaxUse,
# RuntimeKeepFree and MaxFileSec. There is no single canonical value (it is
# site-policy-dependent), so the check requires that at least one of these
# directives is explicitly set to a non-empty value, not left at journald's
# defaults.
_JOURNALD_ROTATION_KEYS = (
    "systemmaxuse",
    "systemkeepfree",
    "runtimemaxuse",
    "runtimekeepfree",
    "maxfilesec",
)


def _evaluate_journald_log_rotation(facts: SystemFacts) -> bool:
    directives = parse_journald_conf(facts.journald_text)
    return any(directives.get(key) for key in _JOURNALD_ROTATION_KEYS)


def _evidence_journald_log_rotation(facts: SystemFacts) -> str:
    directives = parse_journald_conf(facts.journald_text)
    set_keys = [f"{key}={directives[key]}" for key in _JOURNALD_ROTATION_KEYS if directives.get(key)]
    if set_keys:
        return "journald.conf: " + ", ".join(set_keys)
    return "journald.conf: none of SystemMaxUse/SystemKeepFree/RuntimeMaxUse/RuntimeKeepFree/MaxFileSec are set"


# Lines of /etc/shells are matched on `/nologin\b` (word boundary), which
# catches both /sbin/nologin and /usr/sbin/nologin style paths, not just a
# literal "nologin" shell name.
_NOLOGIN_RE = re.compile(r"/nologin\b")


def _evaluate_shells_no_nologin(facts: SystemFacts) -> bool:
    for line in facts.shells_text.splitlines():
        if line.strip().startswith("#"):
            continue
        if _NOLOGIN_RE.search(line):
            return False
    return True


def _evidence_shells_no_nologin(facts: SystemFacts) -> str:
    offending = [
        line.strip()
        for line in facts.shells_text.splitlines()
        if not line.strip().startswith("#") and _NOLOGIN_RE.search(line)
    ]
    if offending:
        return "/etc/shells: nologin listed: " + ", ".join(offending)
    return "/etc/shells: nologin not listed"


def _evaluate_etc_motd_permissions(facts: SystemFacts) -> bool:
    """A missing /etc/motd is a PASS (nothing to protect; plain ubuntu:22.04 ships
    without one), unlike the files that are always expected to exist. When the
    file exists, the permission comparison reuses _permissions_ok(), same as
    every other file-permission check.
    """
    stat = facts.file_stats.get("/etc/motd")
    if stat is None or stat.mode is None:
        return True
    return _permissions_ok(facts, "/etc/motd", 0o644, ("root",))


def _evidence_etc_motd_permissions(facts: SystemFacts) -> str:
    stat = facts.file_stats.get("/etc/motd")
    if stat is None or stat.mode is None:
        return "/etc/motd: absent (not configured -- passes: no motd file to protect)"
    return f"/etc/motd: mode={oct(stat.mode)} uid={stat.uid} gid={stat.gid}({stat.gname})"


def _evaluate_bootloader_config_permissions(facts: SystemFacts) -> bool:
    """/boot/grub/grub.cfg must be uid/gid 0/root and mode 0600 or more
    restrictive. Unlike /etc/motd, a missing or unreadable file fails closed
    via _permissions_ok() (same posture as the shadow/passwd family): an absent
    bootloader config can't be verified secure. Bare debian:12/ubuntu:22.04
    images ship without /boot/grub/grub.cfg (no bootloader in a container), so
    the fixture targets report FAIL for this check; it is exercised in tests
    with a fake grub.cfg.
    """
    return _permissions_ok(facts, "/boot/grub/grub.cfg", 0o600, ("root",))


_evidence_bootloader_config_permissions = _evidence_for_stat("/boot/grub/grub.cfg")


# Group F: remaining sshd_config directives (MACs, MaxStartups) + PAM/
# login.defs checks (pam_unix module family, pam_pwhistory use_authtok,
# login.defs password hashing algorithm). Two assigned candidates were
# dropped -- see the final summary below the CHECKS list.

# MACs treated as weak: broken/short-digest HMACs and the umac-64 family, with
# or without Encrypt-Then-Mac -- same "flagged unconditionally regardless of
# patch level" posture as _WEAK_CIPHER_RE above (the CVE-2023-48795 note
# applies to the etm variants here too).
_WEAK_MACS = {
    "hmac-md5",
    "hmac-md5-96",
    "hmac-ripemd160",
    "hmac-sha1-96",
    "umac-64@openssh.com",
    "hmac-md5-etm@openssh.com",
    "hmac-md5-96-etm@openssh.com",
    "hmac-ripemd160-etm@openssh.com",
    "hmac-sha1-96-etm@openssh.com",
    "umac-64-etm@openssh.com",
    "umac-128-etm@openssh.com",
}


def _evaluate_ssh_macs(facts: SystemFacts) -> bool:
    macs = facts.sshd_config.get("macs", "")
    if not macs:
        return False
    algorithms = {m.strip().lower() for m in macs.split(",")}
    return not (algorithms & _WEAK_MACS)


def _evidence_ssh_macs(facts: SystemFacts) -> str:
    value = _sshd_directive_value(facts, "macs")
    return f"sshd_config: MACs {value}"


def _evaluate_ssh_max_startups(facts: SystemFacts) -> bool:
    """MaxStartups' "start:rate:full" triple (as reported by `sshd -T`) must be
    10:30:60 or more restrictive in every field.
    """
    value = facts.sshd_config.get("maxstartups", "")
    parts = value.split(":")
    if len(parts) != 3:
        return False
    try:
        start, rate, full = (int(p) for p in parts)
    except ValueError:
        return False
    return start <= 10 and rate <= 30 and full <= 60


def _evidence_ssh_max_startups(facts: SystemFacts) -> str:
    value = _sshd_directive_value(facts, "maxstartups")
    return f"sshd_config: MaxStartups {value}"


def _evaluate_login_defs_encrypt_method(facts: SystemFacts) -> bool:
    """ENCRYPT_METHOD in /etc/login.defs must be SHA512 or yescrypt. The match is
    case-insensitive, so the value is upper-cased before comparing.
    """
    value = parse_login_defs(facts.login_defs_text).get("ENCRYPT_METHOD", "")
    return value.upper() in ("SHA512", "YESCRYPT")


def _evidence_login_defs_encrypt_method(facts: SystemFacts) -> str:
    value = parse_login_defs(facts.login_defs_text).get("ENCRYPT_METHOD", "<not set>")
    return f"login.defs: ENCRYPT_METHOD {value}"


def _pam_unix_present(text: str) -> bool:
    return any("pam_unix.so" in line for line in text.splitlines())


def _evaluate_pam_unix_enabled(facts: SystemFacts) -> bool:
    """pam_unix.so must show up in every PAM file in the list. facts.SystemFacts
    collects common-auth/common-account/common-password but not common-session
    or common-session-noninteractive -- same collection gap as
    _pam_unix_nullok_lines above -- so this checks the 3 available files.
    """
    return (
        _pam_unix_present(facts.pam_common_auth)
        and _pam_unix_present(facts.pam_common_account)
        and _pam_unix_present(facts.pam_common_password)
    )


def _evidence_pam_unix_enabled(facts: SystemFacts) -> str:
    auth = "present" if _pam_unix_present(facts.pam_common_auth) else "missing"
    account = "present" if _pam_unix_present(facts.pam_common_account) else "missing"
    password = "present" if _pam_unix_present(facts.pam_common_password) else "missing"
    return f"pam_unix.so: common-auth={auth}, common-account={account}, common-password={password}"


_REMEMBER_RE = re.compile(r"\bremember=\d+\b")


def _pam_unix_remember_lines(facts: SystemFacts) -> list[str]:
    """Lines across common-auth/common-password/common-account that configure
    pam_unix.so with a remember= argument -- remember belongs on
    pam_pwhistory.so (password history), not pam_unix.so. common-session files
    are not collected by facts.py -- same gap as _pam_unix_nullok_lines above.
    """
    offending = []
    for text in (facts.pam_common_auth, facts.pam_common_password, facts.pam_common_account):
        for line in text.splitlines():
            if "pam_unix.so" in line and _REMEMBER_RE.search(line):
                offending.append(line.strip())
    return offending


def _evaluate_pam_unix_no_remember(facts: SystemFacts) -> bool:
    return len(_pam_unix_remember_lines(facts)) == 0


def _evidence_pam_unix_no_remember(facts: SystemFacts) -> str:
    lines = _pam_unix_remember_lines(facts)
    if not lines:
        return "no remember= found on pam_unix.so lines in common-auth/common-password/common-account"
    return "remember= found: " + " | ".join(lines)


def _pam_unix_password_lines(facts: SystemFacts) -> list[str]:
    return [line.strip() for line in facts.pam_common_password.splitlines() if "pam_unix.so" in line]


def _evaluate_pam_unix_strong_password_hashing(facts: SystemFacts) -> bool:
    """The pam_unix.so line in common-password must name sha512 or yescrypt as its
    hashing algorithm. On ubuntu 20.04 only sha512 is accepted; that one case is
    branched on explicitly using facts.os_id/os_version_id (already collected,
    not a new field).
    """
    lines = _pam_unix_password_lines(facts)
    has_sha512 = any("sha512" in line.lower() for line in lines)
    has_yescrypt = any("yescrypt" in line.lower() for line in lines)
    if facts.os_id == "ubuntu" and facts.os_version_id == "20.04":
        return has_sha512
    return has_sha512 or has_yescrypt


def _evidence_pam_unix_strong_password_hashing(facts: SystemFacts) -> str:
    lines = _pam_unix_password_lines(facts)
    return "common-password pam_unix.so line(s): " + (" | ".join(lines) if lines else "<none>")


def _evaluate_pam_unix_use_authtok(facts: SystemFacts) -> bool:
    """The pam_unix.so line in common-password must carry use_authtok."""
    return any("use_authtok" in line for line in _pam_unix_password_lines(facts))


def _evidence_pam_unix_use_authtok(facts: SystemFacts) -> str:
    lines = _pam_unix_password_lines(facts)
    return "common-password pam_unix.so line(s): " + (" | ".join(lines) if lines else "<none>")


def _evaluate_pam_pwhistory_use_authtok(facts: SystemFacts) -> bool:
    """Either the pam_pwhistory.so line in /etc/pam.d/common-password carries
    use_authtok, OR (the newer, pam-configs-driven layout) /etc/security/
    pwhistory.conf sets use_authtok directly -- either location passes.
    facts.pwhistory_text (pwhistory.conf) is already collected for the sibling
    pam_pwhistory checks.
    """
    pwhistory_lines = [line for line in facts.pam_common_password.splitlines() if "pam_pwhistory.so" in line]
    if any("use_authtok" in line for line in pwhistory_lines):
        return True
    for line in facts.pwhistory_text.splitlines():
        stripped = line.strip()
        if stripped.lower().startswith("use_authtok"):
            return True
    return False


def _evidence_pam_pwhistory_use_authtok(facts: SystemFacts) -> str:
    pwhistory_lines = [line.strip() for line in facts.pam_common_password.splitlines() if "pam_pwhistory.so" in line]
    conf_active = [
        line.strip() for line in facts.pwhistory_text.splitlines() if line.strip().lower().startswith("use_authtok")
    ]
    return (
        f"common-password pam_pwhistory.so line(s): {' | '.join(pwhistory_lines) or '<none>'}; "
        f"pwhistory.conf use_authtok: {'set' if conf_active else 'not set'}"
    )


# Group L: sshd_config directives (round 2); see the CHECKS entries below for
# per-check notes.
def _evaluate_ssh_max_auth_tries(facts: SystemFacts) -> bool:
    """MaxAuthTries from `sshd -T` must be 4 or less."""
    value = facts.sshd_config.get("maxauthtries", "")
    try:
        return int(value) <= 4
    except ValueError:
        return False


def _evidence_ssh_max_auth_tries(facts: SystemFacts) -> str:
    value = _sshd_directive_value(facts, "maxauthtries")
    return f"sshd_config: MaxAuthTries {value}"


def _evaluate_ssh_permit_empty_passwords(facts: SystemFacts) -> bool:
    return facts.sshd_config.get("permitemptypasswords", "").lower() == "no"


def _evidence_ssh_permit_empty_passwords(facts: SystemFacts) -> str:
    value = _sshd_directive_value(facts, "permitemptypasswords")
    return f"sshd_config: PermitEmptyPasswords {value}"


def _evaluate_ssh_hostbased_authentication(facts: SystemFacts) -> bool:
    return facts.sshd_config.get("hostbasedauthentication", "").lower() == "no"


def _evidence_ssh_hostbased_authentication(facts: SystemFacts) -> str:
    value = _sshd_directive_value(facts, "hostbasedauthentication")
    return f"sshd_config: HostbasedAuthentication {value}"


def _evaluate_ssh_gssapi_authentication(facts: SystemFacts) -> bool:
    return facts.sshd_config.get("gssapiauthentication", "").lower() == "no"


def _evidence_ssh_gssapi_authentication(facts: SystemFacts) -> str:
    value = _sshd_directive_value(facts, "gssapiauthentication")
    return f"sshd_config: GSSAPIAuthentication {value}"


def _evaluate_ssh_client_alive(facts: SystemFacts) -> bool:
    """Both ClientAliveInterval and ClientAliveCountMax from `sshd -T` must be
    greater than zero -- one Check, both conditions.
    """
    try:
        interval = int(facts.sshd_config.get("clientaliveinterval", ""))
        count_max = int(facts.sshd_config.get("clientalivecountmax", ""))
    except ValueError:
        return False
    return interval > 0 and count_max > 0


def _evidence_ssh_client_alive(facts: SystemFacts) -> str:
    interval = _sshd_directive_value(facts, "clientaliveinterval")
    count_max = _sshd_directive_value(facts, "clientalivecountmax")
    return f"sshd_config: ClientAliveInterval {interval}, ClientAliveCountMax {count_max}"


def _evaluate_ssh_banner(facts: SystemFacts) -> bool:
    """Partial check: only verifies that Banner is set to an absolute path.
    The content of the banner file is not collected by facts.py, so it is not
    inspected. This matches the project's existing precedent for "configured"
    (not "correct value") checks (e.g. _evaluate_pwquality_enforce_for_root,
    _evaluate_sudo_log_file_exists above), which verify a directive is
    present/set rather than judging site-policy-dependent content.
    """
    value = facts.sshd_config.get("banner", "")
    return value.startswith("/")


def _evidence_ssh_banner(facts: SystemFacts) -> str:
    value = _sshd_directive_value(facts, "banner")
    return f"sshd_config: Banner {value} (directive-set only, content not verified)"


def _evaluate_ssh_allow_deny_configured(facts: SystemFacts) -> bool:
    """At least one of AllowUsers/AllowGroups/DenyUsers/DenyGroups must be present
    in `sshd -T` output. The actual list is site policy, so presence of any one
    directive is the machine-checkable bar, same "configured, not judged"
    posture as _evaluate_ssh_banner above.
    """
    return any(
        facts.sshd_config.get(directive, "")
        for directive in ("allowusers", "allowgroups", "denyusers", "denygroups")
    )


def _evidence_ssh_allow_deny_configured(facts: SystemFacts) -> str:
    # Unlike every other _evidence_ssh_* function, an empty sshd_config
    # here is naturally indistinguishable from "sshd present but none of
    # AllowUsers/.../DenyGroups set" -- so this one needs the explicit
    # tri-state check too, not just the shared .get() default, or its
    # evidence text would carry no absent/unknown signal at all.
    state = _sshd_state(facts)
    if state == "absent":
        return "sshd_config: <sshd-not-installed>"
    if state == "unknown":
        return "sshd_config: <sshd-status-unknown>"
    parts = [
        f"{directive}={facts.sshd_config[directive]}"
        for directive in ("allowusers", "allowgroups", "denyusers", "denygroups")
        if facts.sshd_config.get(directive)
    ]
    return "sshd_config: " + (", ".join(parts) if parts else "none of AllowUsers/AllowGroups/DenyUsers/DenyGroups set")
# Group N: unused network service packages batch B + required packages
# (round 2).
#
# Part A (8): same "package must NOT be installed" shape as the
# _packages_absent-based checks above, with the same omission of any
# "installed but disabled" exemption (SystemFacts has no systemd unit-state
# collection).
#
# Part B (3): opposite direction, same installed_packages field.
#   - sudo: `sudo` OR `sudo-ldap` installed.
#   - auditd packages: both `auditd` and `audispd-plugins` required (AND).
#   - AIDE: both `aide` and `aide-common` required (AND).
def _evaluate_cups_not_installed(facts: SystemFacts) -> bool:
    return _packages_absent(facts, "cups")


def _evidence_cups_not_installed(facts: SystemFacts) -> str:
    present = "cups" in facts.installed_packages
    return f"installed_packages: cups {'present' if present else 'absent'}"


def _evaluate_rpcbind_not_installed(facts: SystemFacts) -> bool:
    return _packages_absent(facts, "rpcbind")


def _evidence_rpcbind_not_installed(facts: SystemFacts) -> str:
    present = "rpcbind" in facts.installed_packages
    return f"installed_packages: rpcbind {'present' if present else 'absent'}"


def _evaluate_samba_not_installed(facts: SystemFacts) -> bool:
    return _packages_absent(facts, "samba")


def _evidence_samba_not_installed(facts: SystemFacts) -> str:
    present = "samba" in facts.installed_packages
    return f"installed_packages: samba {'present' if present else 'absent'}"


def _evaluate_snmp_not_installed(facts: SystemFacts) -> bool:
    return _packages_absent(facts, "snmpd")


def _evidence_snmp_not_installed(facts: SystemFacts) -> str:
    present = "snmpd" in facts.installed_packages
    return f"installed_packages: snmpd {'present' if present else 'absent'}"


def _evaluate_tftp_server_not_installed(facts: SystemFacts) -> bool:
    return _packages_absent(facts, "tftpd-hpa")


def _evidence_tftp_server_not_installed(facts: SystemFacts) -> str:
    present = "tftpd-hpa" in facts.installed_packages
    return f"installed_packages: tftpd-hpa {'present' if present else 'absent'}"


def _evaluate_web_proxy_not_installed(facts: SystemFacts) -> bool:
    """The Ubuntu 20.04 variant additionally names squid-openssl. Requiring both
    absent is a safe superset (same reasoning as _packages_absent's own
    docstring, and the same pattern as telnet/inetutils-telnet and ftp/tnftp).
    """
    return _packages_absent(facts, "squid", "squid-openssl")


def _evidence_web_proxy_not_installed(facts: SystemFacts) -> str:
    present = [p for p in ("squid", "squid-openssl") if p in facts.installed_packages]
    return f"installed_packages: squid/squid-openssl {'present: ' + ','.join(present) if present else 'absent'}"


def _evaluate_web_server_not_installed(facts: SystemFacts) -> bool:
    return _packages_absent(facts, "apache2", "nginx")


def _evidence_web_server_not_installed(facts: SystemFacts) -> str:
    present = [p for p in ("apache2", "nginx") if p in facts.installed_packages]
    return f"installed_packages: apache2/nginx {'present: ' + ','.join(present) if present else 'absent'}"


def _evaluate_autofs_not_installed(facts: SystemFacts) -> bool:
    return _packages_absent(facts, "autofs")


def _evidence_autofs_not_installed(facts: SystemFacts) -> str:
    present = "autofs" in facts.installed_packages
    return f"installed_packages: autofs {'present' if present else 'absent'}"


def _evaluate_sudo_installed(facts: SystemFacts) -> bool:
    return "sudo" in facts.installed_packages or "sudo-ldap" in facts.installed_packages


def _evidence_sudo_installed(facts: SystemFacts) -> str:
    present = [p for p in ("sudo", "sudo-ldap") if p in facts.installed_packages]
    return f"installed_packages: sudo/sudo-ldap {'present: ' + ','.join(present) if present else 'absent'}"


def _evaluate_auditd_packages_installed(facts: SystemFacts) -> bool:
    return "auditd" in facts.installed_packages and "audispd-plugins" in facts.installed_packages


def _evidence_auditd_packages_installed(facts: SystemFacts) -> str:
    missing = [p for p in ("auditd", "audispd-plugins") if p not in facts.installed_packages]
    return f"installed_packages: auditd/audispd-plugins {'both present' if not missing else 'missing: ' + ','.join(missing)}"


def _evaluate_aide_installed(facts: SystemFacts) -> bool:
    return "aide" in facts.installed_packages and "aide-common" in facts.installed_packages


def _evidence_aide_installed(facts: SystemFacts) -> str:
    missing = [p for p in ("aide", "aide-common") if p not in facts.installed_packages]
    return f"installed_packages: aide/aide-common {'both present' if not missing else 'missing: ' + ','.join(missing)}"


# Group Q: passwd/group consistency (round 2). Reuses _passwd_fields()/
# _group_fields() from Group B above -- no new parsing helpers, no facts.py
# changes.
#
# A duplicate-user-name check was looked at and not implemented: one of the
# supported documents describes it against /etc/group instead of
# /etc/passwd, so a single evaluator could not be faithful to both variants.


def _evaluate_no_duplicate_uids(facts: SystemFacts) -> bool:
    """Fails if any UID (passwd field 3) appears more than once."""
    uids = [fields[2] for fields in _passwd_fields(facts.passwd_text)]
    return len(uids) == len(set(uids))


def _evidence_no_duplicate_uids(facts: SystemFacts) -> str:
    uids = [fields[2] for fields in _passwd_fields(facts.passwd_text)]
    dupes = sorted(uid for uid, count in Counter(uids).items() if count > 1)
    return f"/etc/passwd: duplicate UIDs: {', '.join(dupes) or '<none>'}"


def _evaluate_no_duplicate_gids(facts: SystemFacts) -> bool:
    """Fails if any GID (group field 3) appears more than once."""
    gids = [fields[2] for fields in _group_fields(facts.group_text)]
    return len(gids) == len(set(gids))


def _evidence_no_duplicate_gids(facts: SystemFacts) -> str:
    gids = [fields[2] for fields in _group_fields(facts.group_text)]
    dupes = sorted(gid for gid, count in Counter(gids).items() if count > 1)
    return f"/etc/group: duplicate GIDs: {', '.join(dupes) or '<none>'}"


def _evaluate_no_duplicate_group_names(facts: SystemFacts) -> bool:
    """Fails if any group name (group field 1) appears more than once."""
    names = [fields[0] for fields in _group_fields(facts.group_text)]
    return len(names) == len(set(names))


def _evidence_no_duplicate_group_names(facts: SystemFacts) -> str:
    names = [fields[0] for fields in _group_fields(facts.group_text)]
    dupes = sorted(name for name, count in Counter(names).items() if count > 1)
    return f"/etc/group: duplicate group names: {', '.join(dupes) or '<none>'}"


def _evaluate_passwd_groups_exist_in_group(facts: SystemFacts) -> bool:
    """Every primary GID referenced in /etc/passwd (field 4) must exist as a GID
    (field 3) in /etc/group.
    """
    group_gids = {fields[2] for fields in _group_fields(facts.group_text)}
    passwd_gids = {fields[3] for fields in _passwd_fields(facts.passwd_text)}
    return passwd_gids <= group_gids


def _evidence_passwd_groups_exist_in_group(facts: SystemFacts) -> str:
    group_gids = {fields[2] for fields in _group_fields(facts.group_text)}
    orphans = [
        f"{fields[0]} (GID {fields[3]})" for fields in _passwd_fields(facts.passwd_text) if fields[3] not in group_gids
    ]
    return f"/etc/passwd: users with GID missing from /etc/group: {', '.join(orphans) or '<none>'}"


def _evaluate_shadow_group_empty(facts: SystemFacts) -> bool:
    """The `shadow` group's member list (/etc/group field 4) must be empty, AND no
    account's primary GID (/etc/passwd field 4) may equal the shadow group's
    GID. Both conditions must hold for PASS.
    """
    shadow_groups = [fields for fields in _group_fields(facts.group_text) if fields[0] == "shadow"]
    if not shadow_groups:
        return True
    fields = shadow_groups[0]
    members = fields[3] if len(fields) > 3 else ""
    if members.strip():
        return False
    shadow_gid = fields[2]
    primary_gid_users = [f[0] for f in _passwd_fields(facts.passwd_text) if f[3] == shadow_gid]
    return not primary_gid_users


def _evidence_shadow_group_empty(facts: SystemFacts) -> str:
    shadow_groups = [fields for fields in _group_fields(facts.group_text) if fields[0] == "shadow"]
    if not shadow_groups:
        return "/etc/group: no shadow group present"
    fields = shadow_groups[0]
    members = fields[3] if len(fields) > 3 else ""
    shadow_gid = fields[2]
    primary_gid_users = [f[0] for f in _passwd_fields(facts.passwd_text) if f[3] == shadow_gid]
    return (
        f"/etc/group: shadow group members: {members or '<none>'}; "
        f"primary-GID-shadow users: {', '.join(primary_gid_users) or '<none>'}"
    )


# Group P: shadow/login.defs/sudoers/pwquality (round 2). Reuses
# _passwd_fields() (the shared shadow/passwd colon-parser already used by
# Group B above) and parse_login_defs()/parse_pwquality_conf() -- no new
# facts.py fields needed.


def _has_real_password(fields: list[str]) -> bool:
    """Shared by every /etc/shadow check below that only applies to accounts with
    a real password hash: shadow field 2 (colon index 1) matching `^\\$.+\\$`,
    which skips locked (`!`/`!!`), empty, or `*`-disabled accounts.
    """
    return len(fields) > 1 and bool(re.match(r"^\$.+\$", fields[1]))


def _awk_int(value: str) -> int:
    """Mirrors awk's own numeric coercion of a bare field reference: an empty
    string (a shadow field genuinely left blank -- INACTIVE/PASS_MAX_DAYS/
    PASS_WARN_AGE never explicitly set for that account) numifies to 0, not an
    error.
    """
    return int(value) if value else 0


def _evaluate_inactive_password_lock(facts: SystemFacts) -> bool:
    """Every password-having user's shadow field 7 (INACTIVE) must be in [0, 45]."""
    for fields in _passwd_fields(facts.shadow_text):
        if len(fields) < 7 or not _has_real_password(fields):
            continue
        inactive = _awk_int(fields[6])
        if inactive > 45 or inactive < 0:
            return False
    return True


# Group K: full-filesystem scans (world-writable / unowned) and root's
# PATH -- a different kind of check from every group above (a dynamic
# `find` over the whole filesystem, or a dynamically-shaped PATH string,
# rather than a fixed set of paths/config files), backed by the 3 new
# facts.py text blocks documented there.
def _parse_world_writable(text: str) -> tuple[list[str], list[str]]:
    """Parses facts.world_writable_text ("f:<mode>:<path>" or "d:<mode>:<path>"
    lines, one per world-writable file/dir found) into (world-writable files,
    world-writable directories missing the sticky bit): a world-writable
    directory only counts as a failure if the sticky bit is NOT set.
    """
    files = []
    bad_dirs = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        parts = line.split(":", 2)
        if len(parts) != 3:
            continue
        ftype, mode_str, path = parts
        try:
            mode = int(mode_str, 8)
        except ValueError:
            continue
        if ftype == "f":
            files.append(path)
        elif ftype == "d" and not (mode & 0o1000):
            bad_dirs.append(path)
    return files, bad_dirs


def _evaluate_world_writable_secured(facts: SystemFacts) -> bool:
    """Finds every world-writable (mode & 0002) file or directory under every real
    mount point. PASS requires zero world-writable files, and every
    world-writable directory must carry the sticky bit (01000).
    """
    files, bad_dirs = _parse_world_writable(facts.world_writable_text)
    return not files and not bad_dirs


def _evidence_world_writable_secured(facts: SystemFacts) -> str:
    files, bad_dirs = _parse_world_writable(facts.world_writable_text)
    if not files and not bad_dirs:
        return "no world-writable files; sticky bit set on all world-writable directories"
    parts = []
    if files:
        parts.append(f"world-writable files: {', '.join(files)}")
    if bad_dirs:
        parts.append(f"world-writable directories without sticky bit: {', '.join(bad_dirs)}")
    return "; ".join(parts)


def _parse_unowned(text: str) -> list[str]:
    """Parses facts.unowned_text ("f:<uid>:<gid>:<path>" or "d:<uid>:<gid>:<path>"
    lines) into a flat path list. Unowned and ungrouped files are the same
    PASS/FAIL condition here (zero of either), so a single combined list is
    enough; evidence still reports the raw path either way.
    """
    paths = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        parts = line.split(":", 3)
        if len(parts) != 4:
            continue
        paths.append(parts[3])
    return paths


def _evaluate_no_unowned_files(facts: SystemFacts) -> bool:
    """Every file/dir under every real mount point must have a resolvable owning
    user and group. PASS requires zero results.
    """
    return len(_parse_unowned(facts.unowned_text)) == 0


def _evidence_no_unowned_files(facts: SystemFacts) -> str:
    paths = _parse_unowned(facts.unowned_text)
    if not paths:
        return "no files or directories without an owner or group found"
    return f"unowned/ungrouped: {', '.join(paths)}"


def _root_path_entries(facts: SystemFacts) -> tuple[str, list[tuple[str, dict[str, str] | None]]]:
    """Splits facts.root_path_probe_text into (raw PATH string, per-
    component detail) -- the first line is the raw PATH, each following
    line is that component's stat detail in the same order (see facts.py's
    comment above root_path_probe_text for why the two line up
    positionally). A component's detail is None when it wasn't a directory
    that exists (covers a missing path, a non-directory, an empty "::" /
    trailing ":" component, and "." itself, which is also always a valid
    existing directory -- the caller rejects it by name, not by this).
    """
    lines = facts.root_path_probe_text.splitlines()
    raw_path = lines[0] if lines else ""
    entries: list[tuple[str, dict[str, str] | None]] = []
    for line in lines[1:]:
        if line.startswith("DIR:"):
            path, _, stat_text = line[len("DIR:") :].partition(":")
            fields = dict(tok.split("=", 1) for tok in stat_text.split() if "=" in tok)
            entries.append((path, fields))
        elif line.startswith("NODIR:"):
            entries.append((line[len("NODIR:") :], None))
    return raw_path, entries


_ROOT_PATH_PMASK = 0o022  # reject group/other write


def _evaluate_root_path_integrity(facts: SystemFacts) -> bool:
    """Root's PATH must have no empty ("::") component, no trailing ":", no "."
    (current working directory) component, and every remaining component must
    be an absolute, existing directory owned by root with mode 0755 or
    stricter (no group/other write bit). See facts.py's comment on
    root_path_probe_text for how root's PATH is captured without sudo/su.
    """
    raw_path, entries = _root_path_entries(facts)
    if not raw_path or "::" in raw_path or raw_path.endswith(":"):
        return False
    components = raw_path.split(":")
    if "." in components:
        return False
    if len(entries) != len(components):
        return False
    for path, stat in entries:
        if not path or not path.startswith("/") or stat is None:
            return False
        try:
            mode = int(stat.get("mode", ""), 8)
            uid = int(stat.get("uid", ""))
        except ValueError:
            return False
        if uid != 0 or (mode & _ROOT_PATH_PMASK):
            return False
    return True


def _evidence_inactive_password_lock(facts: SystemFacts) -> str:
    offending = [
        f"{fields[0]} (INACTIVE={fields[6] or 0})"
        for fields in _passwd_fields(facts.shadow_text)
        if len(fields) >= 7
        and _has_real_password(fields)
        and (_awk_int(fields[6]) > 45 or _awk_int(fields[6]) < 0)
    ]
    if offending:
        return "/etc/shadow: INACTIVE outside [0, 45] for: " + ", ".join(offending)
    return "/etc/shadow: all password-having users have INACTIVE in [0, 45]"


_EPOCH = date(1970, 1, 1)


def _evaluate_last_password_change_in_past(facts: SystemFacts) -> bool:
    """For every password-having user, shadow field 3 (days since epoch of last
    password change) must not be in the future. An empty field 3 is treated as
    "not in the future" (0 is never later than today's epoch day).
    """
    today = (datetime.now(timezone.utc).date() - _EPOCH).days
    for fields in _passwd_fields(facts.shadow_text):
        if len(fields) < 3 or not _has_real_password(fields):
            continue
        raw = fields[2]
        if raw == "":
            continue
        try:
            last_change = int(raw)
        except ValueError:
            continue
        if last_change > today:
            return False
    return True


def _evidence_last_password_change_in_past(facts: SystemFacts) -> str:
    today = (datetime.now(timezone.utc).date() - _EPOCH).days
    offending = []
    for fields in _passwd_fields(facts.shadow_text):
        if len(fields) < 3 or not _has_real_password(fields) or fields[2] == "":
            continue
        try:
            last_change = int(fields[2])
        except ValueError:
            continue
        if last_change > today:
            offending.append(f"{fields[0]} (day {last_change}, today is day {today})")
    if offending:
        return "/etc/shadow: last password change in the future for: " + ", ".join(offending)
    return "/etc/shadow: no user's last password change is in the future"


def _evaluate_password_expiration_configured(facts: SystemFacts) -> bool:
    """PASS_MAX_DAYS in /etc/login.defs must be 365 or less, AND every
    password-having user's shadow field 5 must be in the range 1-365.
    """
    value = parse_login_defs(facts.login_defs_text).get("PASS_MAX_DAYS")
    try:
        if int(value) > 365:
            return False
    except (TypeError, ValueError):
        return False
    for fields in _passwd_fields(facts.shadow_text):
        if len(fields) < 5 or not _has_real_password(fields):
            continue
        max_days = _awk_int(fields[4])
        if max_days > 365 or max_days < 1:
            return False
    return True


def _evidence_password_expiration_configured(facts: SystemFacts) -> str:
    value = parse_login_defs(facts.login_defs_text).get("PASS_MAX_DAYS", "<not set>")
    offending = [
        f"{fields[0]} (PASS_MAX_DAYS={fields[4] or 0})"
        for fields in _passwd_fields(facts.shadow_text)
        if len(fields) >= 5
        and _has_real_password(fields)
        and (_awk_int(fields[4]) > 365 or _awk_int(fields[4]) < 1)
    ]
    return f"login.defs: PASS_MAX_DAYS {value}; /etc/shadow outside (0, 365]: " + (", ".join(offending) or "<none>")


def _evaluate_password_expiration_warning_configured(facts: SystemFacts) -> bool:
    """PASS_WARN_AGE in /etc/login.defs must be 7 or more, AND every
    password-having user's shadow field 6 must be 7 or more.
    """
    value = parse_login_defs(facts.login_defs_text).get("PASS_WARN_AGE")
    try:
        if int(value) < 7:
            return False
    except (TypeError, ValueError):
        return False
    for fields in _passwd_fields(facts.shadow_text):
        if len(fields) < 6 or not _has_real_password(fields):
            continue
        if _awk_int(fields[5]) < 7:
            return False
    return True


def _evidence_password_expiration_warning_configured(facts: SystemFacts) -> str:
    value = parse_login_defs(facts.login_defs_text).get("PASS_WARN_AGE", "<not set>")
    offending = [
        f"{fields[0]} (PASS_WARN_AGE={fields[5] or 0})"
        for fields in _passwd_fields(facts.shadow_text)
        if len(fields) >= 6 and _has_real_password(fields) and _awk_int(fields[5]) < 7
    ]
    return f"login.defs: PASS_WARN_AGE {value}; /etc/shadow below 7: " + (", ".join(offending) or "<none>")


def _valid_login_shells(facts: SystemFacts) -> set[str]:
    """Working login shells listed in /etc/shells -- excludes any nologin-style
    entry (basename "nologin"). Shared by the system-account shell check and
    the locked-account check.
    """
    shells = set()
    for line in facts.shells_text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped.rsplit("/", 1)[-1] == "nologin":
            continue
        shells.add(stripped)
    return shells


def _uid_min(facts: SystemFacts) -> int | None:
    value = parse_login_defs(facts.login_defs_text).get("UID_MIN")
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


_SYSTEM_ACCOUNT_LOGIN_SHELL_EXCLUDED_NAMES = ("root", "halt", "sync", "shutdown", "nfsnobody")


def _system_accounts_with_valid_shell(facts: SystemFacts) -> list[str]:
    uid_min = _uid_min(facts)
    if uid_min is None:
        return []
    valid_shells = _valid_login_shells(facts)
    offending = []
    for fields in _passwd_fields(facts.passwd_text):
        if len(fields) < 7:
            continue
        name, uid_str, shell = fields[0], fields[2], fields[-1]
        if name in _SYSTEM_ACCOUNT_LOGIN_SHELL_EXCLUDED_NAMES:
            continue
        try:
            uid = int(uid_str)
        except ValueError:
            continue
        if not (uid < uid_min or uid == 65534):
            continue
        if shell in valid_shells:
            offending.append(f"{name} (uid={uid}, shell={shell})")
    return offending


def _evaluate_system_accounts_no_valid_shell(facts: SystemFacts) -> bool:
    """System accounts (UID < login.defs' UID_MIN, or UID 65534) other than the
    excluded names (root, halt, sync, shutdown, nfsnobody) must not have a shell
    from /etc/shells' valid set (see _valid_login_shells()). Fails closed
    (can't be evaluated as compliant) if UID_MIN isn't set in login.defs,
    since the condition depends on it entirely.
    """
    if _uid_min(facts) is None:
        return False
    return len(_system_accounts_with_valid_shell(facts)) == 0


def _evidence_system_accounts_no_valid_shell(facts: SystemFacts) -> str:
    uid_min = _uid_min(facts)
    offending = _system_accounts_with_valid_shell(facts)
    return f"login.defs: UID_MIN {uid_min if uid_min is not None else '<not set>'}; system accounts with a valid login shell: " + (
        ", ".join(offending) or "<none>"
    )


def _accounts_without_valid_shell_not_locked(facts: SystemFacts) -> list[str]:
    valid_shells = _valid_login_shells(facts)
    # Confirmed empirically against a live container: `passwd -S` reports
    # "L" (locked) for a shadow field 2 starting with either "!" (the
    # conventional lock marker) or "*" (the convention for system accounts
    # that were never given a real password) -- not "!" alone.
    locked = {
        fields[0]: fields[1].startswith(("!", "*"))
        for fields in _passwd_fields(facts.shadow_text)
        if len(fields) > 1
    }
    offending = []
    for fields in _passwd_fields(facts.passwd_text):
        if len(fields) < 7:
            continue
        name, shell = fields[0], fields[-1]
        if name == "root" or shell in valid_shells:
            continue
        if not locked.get(name, False):
            offending.append(f"{name} (shell={shell})")
    return offending


def _evaluate_accounts_without_shell_locked(facts: SystemFacts) -> bool:
    """Every non-root account whose shell isn't in the valid-shell set (see
    _valid_login_shells()) must be locked. The lock state is read straight off
    /etc/shadow's own password field (a `!`/`!!`-prefixed hash = locked)
    instead of shelling out to `passwd -S`, the same substitution facts.py's
    own docstring establishes for every check in this module; no live command
    runs here.
    """
    return len(_accounts_without_valid_shell_not_locked(facts)) == 0


def _evidence_accounts_without_shell_locked(facts: SystemFacts) -> str:
    offending = _accounts_without_valid_shell_not_locked(facts)
    if offending:
        return "/etc/passwd: accounts without a valid shell and not locked: " + ", ".join(offending)
    return "/etc/passwd: every non-root account without a valid shell is locked"


def _sudoers_defaults_tokens(line: str) -> list[str]:
    """Splits a plain global `Defaults <comma-separated-options>` active sudoers
    line into its individual option tokens (e.g. "env_reset,mail_badpass,use_pty"
    -> ["env_reset", "mail_badpass", "use_pty"]) -- only that global form is
    handled (not the `Defaults:user`/`Defaults@host` scoped forms).
    """
    parts = line.split("#", 1)[0].split(None, 1)
    if len(parts) < 2 or parts[0].lower() != "defaults":
        return []
    return [token.strip() for token in parts[1].split(",")]


def _evaluate_sudo_use_pty(facts: SystemFacts) -> bool:
    """A `Defaults ... use_pty` line must be present in /etc/sudoers, AND no
    `Defaults ... !use_pty` (negated) line may be present. facts.sudoers_text
    only covers /etc/sudoers itself, not /etc/sudoers.d/* -- same scope
    limitation accepted for _evaluate_sudo_no_nopasswd and
    _evaluate_sudo_reauthentication_required above.
    """
    has_positive = False
    has_negated = False
    for line in _sudoers_active_lines(facts.sudoers_text):
        for token in _sudoers_defaults_tokens(line):
            if token == "use_pty":
                has_positive = True
            elif token == "!use_pty":
                has_negated = True
    return has_positive and not has_negated


def _evidence_sudo_use_pty(facts: SystemFacts) -> str:
    tokens = [t for line in _sudoers_active_lines(facts.sudoers_text) for t in _sudoers_defaults_tokens(line)]
    if "!use_pty" in tokens:
        return "sudoers: Defaults !use_pty found (negated)"
    if "use_pty" in tokens:
        return "sudoers: Defaults use_pty found"
    return "sudoers: no Defaults use_pty line found"


_PAM_PWQUALITY_DICTCHECK_RE = re.compile(r"\bdictcheck\s*=\s*0\b")


def _evaluate_pwquality_dictcheck(facts: SystemFacts) -> bool:
    """dictcheck must NOT be explicitly set to 0 (disabled), either in
    pwquality.conf or as a pam_pwquality.so module argument on common-password.
    PASS if neither location disables it (dictcheck defaults to enabled when
    left unset).
    """
    value = parse_pwquality_conf(facts.pwquality_text).get("dictcheck")
    if value is not None:
        try:
            if int(value) == 0:
                return False
        except ValueError:
            pass
    for line in facts.pam_common_password.splitlines():
        if "pam_pwquality.so" in line and _PAM_PWQUALITY_DICTCHECK_RE.search(line):
            return False
    return True


def _evidence_pwquality_dictcheck(facts: SystemFacts) -> str:
    value = parse_pwquality_conf(facts.pwquality_text).get("dictcheck", "<not set>")
    pam_line = next(
        (line.strip() for line in facts.pam_common_password.splitlines() if "pam_pwquality.so" in line), None
    )
    return f"pwquality.conf: dictcheck {value}; common-password pam_pwquality.so line: {pam_line or '<none>'}"


# Group R: kernel module availability. PASS if the module's directory doesn't
# exist (or is empty) anywhere under /lib/modules/**/kernel/<type>/<name> --
# "not present on the system at all" is a passing state, no further checks
# needed. If it IS present, PASS requires it to be both not currently loaded
# (lsmod) AND blacklisted + install-false/true (modprobe --showconfig).
# module_type (fs/net/drivers) is a fixed constant per module, hardcoded
# below rather than detected.
_KERNEL_MODULES = [
    ("cramfs", "fs"),
    ("dccp", "net"),
    ("freevxfs", "fs"),
    ("hfs", "fs"),
    ("hfsplus", "fs"),
    ("jffs2", "fs"),
    ("rds", "net"),
    ("sctp", "net"),
    ("squashfs", "fs"),
    ("tipc", "net"),
    ("udf", "fs"),
    ("usb-storage", "drivers"),
]

_KERNEL_MODULES_MODPROBE_MARKER = "---MODPROBE---"
_KERNEL_MODULES_LSMOD_MARKER = "---LSMOD---"


def _kernel_module_sections(text: str) -> tuple[str, str, str]:
    """Splits facts.kernel_modules_text (one `find`/`modprobe --showconfig`/
    `lsmod` round trip, see facts.py) into its three parts."""
    modprobe_idx = text.find(_KERNEL_MODULES_MODPROBE_MARKER)
    lsmod_idx = text.find(_KERNEL_MODULES_LSMOD_MARKER)
    if modprobe_idx == -1 or lsmod_idx == -1:
        return text, "", ""
    return (
        text[:modprobe_idx],
        text[modprobe_idx + len(_KERNEL_MODULES_MODPROBE_MARKER) : lsmod_idx],
        text[lsmod_idx + len(_KERNEL_MODULES_LSMOD_MARKER) :],
    )


def _kernel_module_dir_populated(find_text: str, module_type: str, module_name: str) -> bool:
    """True if /lib/modules/**/kernel/<module_type>/<module_name> exists AND has
    at least one file in it; an empty directory is still "not available".
    Hyphens in module_name (only usb-storage among these 12) map to nested
    path components (drivers/usb/storage/), matching the real kernel module tree.
    """
    subpath = f"kernel/{module_type}/{module_name.replace('-', '/')}/"
    return any(subpath in line for line in find_text.splitlines())


def _kernel_module_loaded(lsmod_text: str, module_name: str) -> bool:
    """lsmod always reports module names with underscores, never hyphens (the
    kernel itself normalizes '-' to '_'), so the name is normalized before
    matching. Matches on the first (name) column only, to avoid e.g. "sctp"
    matching an unrelated "sctp_diag" row.
    """
    probe_name = module_name.replace("-", "_")
    return any(line.split()[:1] == [probe_name] for line in lsmod_text.splitlines())


def _kernel_module_blacklisted_and_disabled(modprobe_text: str, module_name: str) -> bool:
    """modprobe --showconfig output must include BOTH a `blacklist <module>` line
    AND an `install <module> /bin/false` (or /bin/true) line.
    """
    probe_name = re.escape(module_name.replace("-", "_"))
    blacklisted = re.search(rf"^\s*blacklist\s+{probe_name}\b", modprobe_text, re.MULTILINE)
    disabled = re.search(rf"^\s*install\s+{probe_name}\s+(/usr)?/bin/(true|false)\b", modprobe_text, re.MULTILINE)
    return bool(blacklisted) and bool(disabled)


def _evaluate_kernel_module_not_available(facts: SystemFacts, module_type: str, module_name: str) -> bool:
    find_text, modprobe_text, lsmod_text = _kernel_module_sections(facts.kernel_modules_text)
    if not _kernel_module_dir_populated(find_text, module_type, module_name):
        return True
    if _kernel_module_loaded(lsmod_text, module_name):
        return False
    return _kernel_module_blacklisted_and_disabled(modprobe_text, module_name)


def _evidence_kernel_module_not_available(facts: SystemFacts, module_type: str, module_name: str) -> str:
    find_text, modprobe_text, lsmod_text = _kernel_module_sections(facts.kernel_modules_text)
    if not _kernel_module_dir_populated(find_text, module_type, module_name):
        return f"{module_name}: no module directory under /lib/modules/**/kernel/{module_type} (not available)"
    loaded = "loaded" if _kernel_module_loaded(lsmod_text, module_name) else "not loaded"
    disabled = (
        "blacklisted+install-disabled"
        if _kernel_module_blacklisted_and_disabled(modprobe_text, module_name)
        else "not blacklisted/disabled"
    )
    return f"{module_name}: module present under kernel/{module_type}, {loaded}, {disabled}"


def _kernel_module_check(module_name: str, module_type: str) -> "Check":
    return Check(
        id=f"kernel_module_{module_name.replace('-', '_')}_not_available",
        evaluate=lambda facts, n=module_name, t=module_type: _evaluate_kernel_module_not_available(facts, t, n),
        evidence=lambda facts, n=module_name, t=module_type: _evidence_kernel_module_not_available(facts, t, n),
    )


# Group S: two candidates added after the umask check (see comment above
# Group F's CHECKS entries) was found to need a facts.py field this group's
# original scope didn't have. A shell-timeout (TMOUT) candidate was looked at
# and not implemented -- see the module docstring notes below the CHECKS list.
_PAM_WHEEL_RE = re.compile(r"^\s*auth\s+(?:required|requisite)\s+pam_wheel\.so\s+(.*)$", re.IGNORECASE)


def _pam_su_restricted_group(facts: SystemFacts) -> str | None:
    """Returns the group name from an /etc/pam.d/su `auth required|requisite
    pam_wheel.so` line that has both `use_uid` and `group=<name>` among its
    arguments, in either order, or None if no line restricts su this way.
    Duplicated tokens on the same line are not modeled (an edge case no real
    config hits), just "both tokens present".
    """
    for line in facts.pam_su_text.splitlines():
        match = _PAM_WHEEL_RE.match(line)
        if not match:
            continue
        tokens = match.group(1).split()
        has_use_uid = any(token.lower() == "use_uid" for token in tokens)
        group_name = next(
            (token.partition("=")[2] for token in tokens if token.lower().startswith("group=")), None
        )
        if has_use_uid and group_name:
            return group_name
    return None


def _evaluate_su_restricted(facts: SystemFacts) -> bool:
    return _pam_su_restricted_group(facts) is not None


def _evidence_su_restricted(facts: SystemFacts) -> str:
    group_name = _pam_su_restricted_group(facts)
    if group_name is None:
        return "/etc/pam.d/su: no 'auth required|requisite pam_wheel.so ... use_uid ... group=<name>' line found"
    return f"/etc/pam.d/su: group={group_name}"


_ROOT_UMASK_LINE_RE = re.compile(r"^[ \t]*umask[ \t]+(\S+)", re.IGNORECASE | re.MULTILINE)


def _root_umask_weak_lines(facts: SystemFacts) -> list[str]:
    """Lines in root's shell startup files (facts.root_shell_startup_text, the
    concatenation of /root/.bash_profile, /root/.profile, and /root/.bashrc --
    see facts.py's comment on that field for why all three are collected) that
    set a umask weaker than 0027, i.e. permissions less restrictive than 750
    (directories) / 640 (files). Only numeric octal umask values are modeled
    (symbolic u=/g=/o= notation is not).
    """
    offending = []
    for match in _ROOT_UMASK_LINE_RE.finditer(facts.root_shell_startup_text):
        value = match.group(1)
        try:
            umask = int(value, 8)
        except ValueError:
            continue
        if (umask & 0o027) != 0o027:
            offending.append(match.group(0).strip())
    return offending


def _evaluate_root_umask(facts: SystemFacts) -> bool:
    return len(_root_umask_weak_lines(facts)) == 0


def _evidence_root_umask(facts: SystemFacts) -> str:
    offending = _root_umask_weak_lines(facts)
    if offending:
        return "root shell startup files: umask weaker than 027 found: " + " | ".join(offending)
    return "root shell startup files: no umask weaker than 027 found"
def _evidence_root_path_integrity(facts: SystemFacts) -> str:
    raw_path, _ = _root_path_entries(facts)
    return f"root PATH: {raw_path or '<empty>'}"


# Group: audit rule collection (round 4). Each check below looks for one
# specific auditd RULE (not a config file directive) via
# facts.audit_rules_text (facts.py: `cat /etc/audit/rules.d/*.rules
# /etc/audit/audit.rules`). A watched path may be written in two equivalent
# syntaxes: an old `-w <path> -p wa -k <key>` watch rule, or a newer
# `-a always,exit -F path=<path>`/`-F dir=<path>` `-F perm=wa` rule. Every
# evaluate() below that watches a path therefore accepts either form.
#
# A check for privileged (SUID/SGID) commands was investigated and not
# implemented: the set of binaries is target-dependent, so there is no
# deterministic expected rule set to derive.


def _line_matches_all(line: str, patterns: tuple[str, ...]) -> bool:
    return all(re.search(p, line) for p in patterns)


def _any_audit_line_matches(facts: SystemFacts, *patterns: str) -> bool:
    """True if some single line of facts.audit_rules_text matches every regex in
    `patterns` -- order-independent tests of a set of substrings against one
    rule line, not a multi-line sequence.
    """
    return any(_line_matches_all(line, patterns) for line in facts.audit_rules_text.splitlines())


def _path_write_monitored(facts: SystemFacts, path: str) -> bool:
    """True if `path` has a write/attribute-change audit rule watching it, in
    either the old `-w` or new `-F path=`/`-F dir=` form (see the group comment
    above). The `(?=\\s|$)` lookahead after the path (rather than a `\\b`
    boundary) stops "/etc/apparmor" from matching inside an "/etc/apparmor.d"
    line -- a `\\b` boundary alone would still fire there (word char 'r' ->
    non-word '.'), which would wrongly treat the two distinct paths as the same
    rule.
    """
    escaped = re.escape(path.rstrip("/"))
    old = rf"-w\s+{escaped}/?(?=\s)"
    new = rf"-F\s*(?:path|dir)\s*=\s*{escaped}/?(?=\s|$)"
    return _any_audit_line_matches(facts, old, r"-p\s*wa") or _any_audit_line_matches(
        facts, new, r"-F\s*perm\s*=\s*wa"
    )


def _all_paths_watched(facts: SystemFacts, paths: tuple[str, ...]) -> bool:
    return all(_path_write_monitored(facts, p) for p in paths)


def _evidence_paths_watched(paths: tuple[str, ...]) -> Callable[[SystemFacts], str]:
    def _evidence(facts: SystemFacts) -> str:
        parts = [f"{p}: {'watched' if _path_write_monitored(facts, p) else 'NOT watched'}" for p in paths]
        return "audit rules: " + " | ".join(parts)

    return _evidence


_USER_EMULATION_PATTERNS = (
    r"-a\s+always,exit",
    r"-F\s*arch=b(32|64)",
    r"-S\s*execve",
    r"auid!=(unset|-1|4294967295)",
    r"(-C\s*euid!=uid|-C\s*uid!=euid)",
    r"(-k\s+\S+|\bkey=\S+)",
)


def _evaluate_user_emulation_logged(facts: SystemFacts) -> bool:
    """Audit rules must include an execve rule shaped like `-a always,exit -F
    arch=b64 -C euid!=uid -F auid!=unset -S execve -k user_emulation` (both an
    arch=b32 and an arch=b64 variant are expected on a real target; a single
    matching line already proves the rule type is present).
    """
    return _any_audit_line_matches(facts, *_USER_EMULATION_PATTERNS)


def _evidence_user_emulation_logged(facts: SystemFacts) -> str:
    ok = _evaluate_user_emulation_logged(facts)
    return f"audit rules: execve rule (arch, -C euid!=uid, auid!=unset, -k) {'found' if ok else 'NOT found'}"


_TIME_CHANGE_SYSCALL_PATTERNS = (
    r"-a\s+always,exit",
    r"-S\s*\S*(adjtimex|settimeofday|clock_settime)",
)


def _evaluate_time_change_logged(facts: SystemFacts) -> bool:
    """Audit rules must include a syscall rule for adjtimex/settimeofday
    (`-a always,exit -F arch=b64 -S adjtimex,settimeofday -k time-change`), a
    clock_settime rule, *and* a rule watching /etc/localtime for writes (`-w
    /etc/localtime -p wa -k time-change`, or the `-F path=/etc/localtime -F
    perm=wa` form).
    """
    return _any_audit_line_matches(facts, *_TIME_CHANGE_SYSCALL_PATTERNS) and _path_write_monitored(
        facts, "/etc/localtime"
    )


def _evidence_time_change_logged(facts: SystemFacts) -> str:
    syscall_ok = _any_audit_line_matches(facts, *_TIME_CHANGE_SYSCALL_PATTERNS)
    path_ok = _path_write_monitored(facts, "/etc/localtime")
    return (
        f"audit rules: adjtimex/settimeofday/clock_settime rule {'found' if syscall_ok else 'NOT found'}; "
        f"/etc/localtime write-watch {'found' if path_ok else 'NOT found'}"
    )


_SUDO_LOGFILE_VALUE_RE = re.compile(r"(?i)\blogfile\s*=\s*(\"[^\"]+\"|'[^']+'|\S+)")


def _sudo_log_file_path(facts: SystemFacts) -> str | None:
    """Resolves sudo's configured log path from an active `Defaults ...
    logfile=...` line in /etc/sudoers, the same source
    _evaluate_sudo_log_file_exists already checks for.
    """
    for line in _sudoers_active_lines(facts.sudoers_text):
        if not _SUDO_LOGFILE_RE.match(line):
            continue
        match = _SUDO_LOGFILE_VALUE_RE.search(line)
        if not match:
            continue
        value = match.group(1).strip("\"'").rstrip(",").strip()
        if value:
            return value
    return None


def _evaluate_sudo_log_file_logged(facts: SystemFacts) -> bool:
    """Resolves sudo's configured log path, then checks for a rule watching it
    (`-w /var/log/sudo.log -p wa -k sudo_log_file`, or the `-F path=... -F
    perm=wa` form). Fails closed if no `Defaults ... logfile=...` line is
    active in sudoers -- same posture as _evaluate_sudo_log_file_exists, since
    there is then no path to watch.
    """
    path = _sudo_log_file_path(facts)
    return bool(path) and _path_write_monitored(facts, path)


def _evidence_sudo_log_file_logged(facts: SystemFacts) -> str:
    path = _sudo_log_file_path(facts)
    if not path:
        return "sudoers: no Defaults logfile= line found -- no path to watch"
    watched = _path_write_monitored(facts, path)
    return f"sudo log file {path}: write-watch {'found' if watched else 'NOT found'}"


_MAC_POLICY_PATHS = ("/etc/apparmor", "/etc/apparmor.d")


def _evaluate_mac_policy_logged(facts: SystemFacts) -> bool:
    """Audit rules must watch both /etc/apparmor/ and /etc/apparmor.d/ for writes
    (`-w /etc/apparmor/ -p wa -k MAC-policy`, `-w /etc/apparmor.d/ -p wa -k
    MAC-policy`, or the `-F path=`/`-F dir=` forms).
    """
    return _all_paths_watched(facts, _MAC_POLICY_PATHS)


_evidence_mac_policy_logged = _evidence_paths_watched(_MAC_POLICY_PATHS)


_LOGIN_PATHS = ("/var/log/lastlog", "/var/run/faillock")


def _evaluate_logins_logged(facts: SystemFacts) -> bool:
    """Audit rules must watch both /var/log/lastlog and /var/run/faillock for
    writes (`-w /var/log/lastlog -p wa -k logins`, or the `-F path=... -F
    perm=wa` equivalents).
    """
    return _all_paths_watched(facts, _LOGIN_PATHS)


_evidence_logins_logged = _evidence_paths_watched(_LOGIN_PATHS)


_SESSION_PATHS = ("/var/run/utmp", "/var/log/wtmp", "/var/log/btmp")


def _evaluate_session_logged(facts: SystemFacts) -> bool:
    """Audit rules must watch /var/run/utmp, /var/log/wtmp and /var/log/btmp for
    writes (`-w /var/run/utmp -p wa -k session`, etc., or the `-F path=... -F
    perm=wa` equivalents).
    """
    return _all_paths_watched(facts, _SESSION_PATHS)


_evidence_session_logged = _evidence_paths_watched(_SESSION_PATHS)


def _evaluate_mounts_logged(facts: SystemFacts) -> bool:
    """With UID_MIN from login.defs, audit rules must include a mount syscall rule
    shaped like `-a always,exit -F arch=b64 -S mount -F auid>=$UID_MIN -F
    auid!=unset -k mounts`. Fails closed if UID_MIN isn't set in login.defs,
    since the condition depends on it entirely.
    """
    uid_min = _uid_min(facts)
    if uid_min is None:
        return False
    patterns = (
        r"-a\s+always,exit",
        r"-S\s*\S*mount",
        rf"auid>=\s*{uid_min}\b",
        r"auid!=(unset|-1|4294967295)",
        r"(-k\s+\S+|\bkey=\S+)",
    )
    return _any_audit_line_matches(facts, *patterns)


def _evidence_mounts_logged(facts: SystemFacts) -> str:
    uid_min = _uid_min(facts)
    if uid_min is None:
        return "login.defs: UID_MIN not set -- can't evaluate mounts audit rule"
    ok = _evaluate_mounts_logged(facts)
    return f"audit rules: mount syscall rule (auid>={uid_min}) {'found' if ok else 'NOT found'}"


def _access_rule_present(facts: SystemFacts, uid_min: int, exit_code: str) -> bool:
    patterns = (
        r"-a\s+always,exit",
        r"creat",
        r"open",
        r"truncate",
        rf"auid>=\s*{uid_min}\b",
        r"auid!=(unset|-1|4294967295)",
        rf"exit=-{exit_code}\b",
        r"(-k\s+\S+|\bkey=\S+)",
    )
    return _any_audit_line_matches(facts, *patterns)


def _evaluate_unsuccessful_file_access_logged(facts: SystemFacts) -> bool:
    """With login.defs' UID_MIN, audit rules must include two separate rules --
    one with `-F exit=-EACCES`, one with `-F exit=-EPERM` -- each shaped like
    `-a always,exit -F arch=b64 -S creat,open,openat,truncate,ftruncate -F
    exit=-EACCES -F auid>=$UID_MIN -F auid!=unset -k access`. Fails closed if
    UID_MIN isn't set in login.defs.
    """
    uid_min = _uid_min(facts)
    if uid_min is None:
        return False
    return _access_rule_present(facts, uid_min, "EACCES") and _access_rule_present(facts, uid_min, "EPERM")


def _evidence_unsuccessful_file_access_logged(facts: SystemFacts) -> str:
    uid_min = _uid_min(facts)
    if uid_min is None:
        return "login.defs: UID_MIN not set -- can't evaluate access audit rules"
    eacces_ok = _access_rule_present(facts, uid_min, "EACCES")
    eperm_ok = _access_rule_present(facts, uid_min, "EPERM")
    return (
        f"audit rules (auid>={uid_min}): EACCES rule {'found' if eacces_ok else 'NOT found'}; "
        f"EPERM rule {'found' if eperm_ok else 'NOT found'}"
    )
# Group V: three more candidates from docs/architecture/checks-backlog.md.
#
# A log-file-permissions candidate was looked at and not implemented: the
# supported documents disagree on which log files may be world-readable, so
# no single evaluator would match all of them.


def _evaluate_single_time_sync_daemon(facts: SystemFacts) -> bool:
    """Exactly one of chrony.service and systemd-timesyncd.service must be enabled
    and active -- both or neither FAILs. `systemctl` can't report a real
    enabled/active state in an unprivileged container without systemd as PID 1,
    so this maps the same "exactly one" condition onto package presence
    (facts.installed_packages) instead -- the same package-presence
    substitution used by the "package X is not in use" family above, just
    requiring exactly one hit instead of zero.
    """
    chrony = "chrony" in facts.installed_packages
    timesyncd = "systemd-timesyncd" in facts.installed_packages
    return chrony != timesyncd


def _evidence_single_time_sync_daemon(facts: SystemFacts) -> str:
    chrony = "chrony" in facts.installed_packages
    timesyncd = "systemd-timesyncd" in facts.installed_packages
    return (
        f"installed_packages: chrony={'present' if chrony else 'absent'}, "
        f"systemd-timesyncd={'present' if timesyncd else 'absent'}"
    )


def _evaluate_audit_processes_prior_to_auditd(facts: SystemFacts) -> bool:
    """No `linux` line in any grub.cfg under /boot may lack `audit=1`. A container
    has no /boot/grub/grub.cfg at all (no bootloader), so nothing matches and
    the check is a legitimate vacuous PASS, same precedent as the kernel-module
    checks.
    """
    return facts.boot_grub_audit_text.strip() == ""


def _evidence_audit_processes_prior_to_auditd(facts: SystemFacts) -> str:
    text = facts.boot_grub_audit_text.strip()
    return f"grub.cfg 'linux' lines missing audit=1: {text or '<none -- no grub.cfg found>'}"


# checks-backlog.md Group B, both resolved: see the comment above
# facts.timesyncd_text and facts.journal_remote_status_text for why each is
# implementable without infra changes.


def _evaluate_timesyncd_authorized_timeserver(facts: SystemFacts) -> bool:
    """Both NTP= and FallbackNTP= must resolve, in the merged timesyncd.conf, to a
    non-blank value -- the check doesn't validate *which* server, just that one
    is actually configured. Reuses parse_pwquality_conf() -- same "key = value,
    comments/blank skipped, later line wins" ini format timesyncd.conf uses.
    """
    directives = parse_pwquality_conf(facts.timesyncd_text)
    return bool(directives.get("ntp")) and bool(directives.get("fallbackntp"))


def _evidence_timesyncd_authorized_timeserver(facts: SystemFacts) -> str:
    directives = parse_pwquality_conf(facts.timesyncd_text)
    ntp = directives.get("ntp", "<not set>")
    fallback = directives.get("fallbackntp", "<not set>")
    return f"timesyncd.conf: NTP={ntp!r}, FallbackNTP={fallback!r}"


def _evaluate_journal_remote_not_in_use(facts: SystemFacts) -> bool:
    """Neither the systemd-journal-remote socket nor service may be enabled or
    active. See the comment above facts.journal_remote_status_text for why a
    systemd-less container's `systemctl` failure legitimately satisfies that
    condition rather than just approximating it.
    """
    return facts.journal_remote_status_text.strip() == ""


def _evidence_journal_remote_not_in_use(facts: SystemFacts) -> str:
    text = facts.journal_remote_status_text.strip()
    return f"systemctl is-enabled/is-active systemd-journal-remote: {text or '<nothing enabled or active>'}"


# checks-backlog.md "Grupo C -- systemd real" (6 candidates). Four of the 6
# are gated on the daemon being in use on the target, so a target that never
# installed a given daemon passes that daemon's check vacuously (same
# substitution already used by _evaluate_single_time_sync_daemon and
# _evaluate_journal_remote_not_in_use above) rather than failing. Only 2 of
# the 6 are unconditional.
def _parse_systemd_service_status(text: str) -> dict[str, str]:
    """Parses facts.systemd_service_status_text's `--MARKER--`-delimited
    sections (same "one text field, self-parsed sub-markers" shape as
    kernel_modules_text/audit_conf_text) into a lowercase-keyed dict, e.g.
    {"auditd_enabled": "enabled", "cron_active": "active", ...}.
    """
    sections = (
        "AUDITD_ENABLED", "AUDITD_ACTIVE",
        "CHRONY_ENABLED", "CHRONY_ACTIVE",
        "CRON_ENABLED", "CRON_ACTIVE",
        "TIMESYNCD_ENABLED", "TIMESYNCD_ACTIVE",
    )
    markers = {s: f"--{s}--" for s in sections}
    hits = sorted((text.find(m), s) for s, m in markers.items() if text.find(m) != -1)
    out = {}
    for i, (pos, s) in enumerate(hits):
        start = pos + len(markers[s])
        end = hits[i + 1][0] if i + 1 < len(hits) else len(text)
        out[s.lower()] = text[start:end].strip()
    return out


def _evaluate_auditd_enabled_active(facts: SystemFacts) -> bool:
    """Unconditional: `systemctl is-enabled auditd` and `systemctl is-active
    auditd` must both report enabled/active. A target that never installed
    auditd fails this closed, same posture as every other auditd-absent check
    in this module.
    """
    status = _parse_systemd_service_status(facts.systemd_service_status_text)
    return status.get("auditd_enabled") == "enabled" and status.get("auditd_active") == "active"


def _evidence_auditd_enabled_active(facts: SystemFacts) -> str:
    status = _parse_systemd_service_status(facts.systemd_service_status_text)
    return f"systemctl auditd: is-enabled={status.get('auditd_enabled')!r} is-active={status.get('auditd_active')!r}"


def _evaluate_chrony_enabled_active(facts: SystemFacts) -> bool:
    """Gated on chrony being in use: a target that never installed chrony (e.g.
    one using systemd-timesyncd instead, per _evaluate_single_time_sync_daemon's
    "exactly one" rule) has nothing to check, a legitimate vacuous PASS.
    """
    if "chrony" not in facts.installed_packages:
        return True
    status = _parse_systemd_service_status(facts.systemd_service_status_text)
    return status.get("chrony_enabled") == "enabled" and status.get("chrony_active") == "active"


def _evidence_chrony_enabled_active(facts: SystemFacts) -> str:
    if "chrony" not in facts.installed_packages:
        return "chrony: not installed (only evaluated when chrony is in use)"
    status = _parse_systemd_service_status(facts.systemd_service_status_text)
    return f"systemctl chrony: is-enabled={status.get('chrony_enabled')!r} is-active={status.get('chrony_active')!r}"


def _evaluate_chrony_runs_as_chrony_user(facts: SystemFacts) -> bool:
    """No chronyd process may run as a user other than `_chrony`. Unconditional on
    package presence (unlike the check above): no chronyd process running at all
    naturally produces nothing to flag, same vacuous-pass-by-absence precedent
    as boot_grub_audit_text.
    """
    return facts.chrony_process_user_text.strip() == ""


def _evidence_chrony_runs_as_chrony_user(facts: SystemFacts) -> str:
    text = facts.chrony_process_user_text.strip()
    return f"chronyd processes not owned by _chrony: {text or '<none>'}"


def _evaluate_cron_enabled_active(facts: SystemFacts) -> bool:
    """Gated on cron being installed -- same substitution as the chrony check
    above, keyed on the "cron" package.
    """
    if "cron" not in facts.installed_packages:
        return True
    status = _parse_systemd_service_status(facts.systemd_service_status_text)
    return status.get("cron_enabled") == "enabled" and status.get("cron_active") == "active"


def _evidence_cron_enabled_active(facts: SystemFacts) -> str:
    if "cron" not in facts.installed_packages:
        return "cron: not installed (only evaluated when cron is installed)"
    status = _parse_systemd_service_status(facts.systemd_service_status_text)
    return f"systemctl cron: is-enabled={status.get('cron_enabled')!r} is-active={status.get('cron_active')!r}"


def _evaluate_timesyncd_enabled_active(facts: SystemFacts) -> bool:
    """Gated on systemd-timesyncd being in use -- same substitution as the
    chrony/cron checks above, keyed on the "systemd-timesyncd" package (mutually
    exclusive with chrony per _evaluate_single_time_sync_daemon, so on any target
    that chose chrony this is a legitimate vacuous PASS, not a gap).
    """
    if "systemd-timesyncd" not in facts.installed_packages:
        return True
    status = _parse_systemd_service_status(facts.systemd_service_status_text)
    return status.get("timesyncd_enabled") == "enabled" and status.get("timesyncd_active") == "active"


def _evidence_timesyncd_enabled_active(facts: SystemFacts) -> str:
    if "systemd-timesyncd" not in facts.installed_packages:
        return "systemd-timesyncd: not installed (only evaluated when it is in use)"
    status = _parse_systemd_service_status(facts.systemd_service_status_text)
    return f"systemctl systemd-timesyncd: is-enabled={status.get('timesyncd_enabled')!r} is-active={status.get('timesyncd_active')!r}"


def _evaluate_audit_rules_running_matches_disk(facts: SystemFacts) -> bool:
    """Unconditional: `augenrules --check` must print exactly "No change". A
    target without augenrules installed (auditd absent) gets a shell error here
    instead -- fails closed, same posture as every other auditd-absent check in
    this module.
    """
    return "no change" in facts.audit_rules_sync_text.strip().lower()


def _evidence_audit_rules_running_matches_disk(facts: SystemFacts) -> str:
    text = facts.audit_rules_sync_text.strip()
    return f"augenrules --check: {text or '<no output>'}"


# checks-backlog.md Group C's partition family: 19 "<option> set on <mount>"
# checks + 7 "separate partition for <mount>" checks (/tmp and /dev/shm
# included).
def parse_mounts(text: str) -> dict[str, str]:
    """Parses facts.mounts_text (`findmnt -kn <target> -o TARGET,SOURCE,
    FSTYPE,OPTIONS`, one line per candidate mount that's actually a real,
    separate mount -- see the comment above that field in facts.py). Maps
    mount point -> its raw comma-separated OPTIONS string; a target absent
    from this dict isn't a separate mount at all.
    """
    mounts = {}
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 4:
            continue
        target, _source, _fstype, options = parts[:4]
        mounts[target] = options
    return mounts


def _evaluate_mount_option(facts: SystemFacts, target: str, option: str) -> bool:
    """If <target> is a real, separate mount, its options must include <option>.
    A target that isn't a separate mount at all has nothing to check, a
    legitimate vacuous PASS, same "grep against something that might not be
    there" precedent used throughout this module.
    """
    options = parse_mounts(facts.mounts_text).get(target)
    return options is None or option in options.split(",")


def _evidence_mount_option(facts: SystemFacts, target: str, option: str) -> str:
    options = parse_mounts(facts.mounts_text).get(target)
    if options is None:
        return f"{target}: not a separate mount (option {option!r} check is vacuous)"
    has = "has" if option in options.split(",") else "missing"
    return f"{target}: mount options = {options} ({has} {option!r})"


def _mount_option_check(check_id: str, target: str, option: str) -> "Check":
    return Check(
        id=check_id,
        evaluate=lambda facts, t=target, o=option: _evaluate_mount_option(facts, t, o),
        evidence=lambda facts, t=target, o=option: _evidence_mount_option(facts, t, o),
    )


# 19 candidates: (check id, mount target, required option). noexec is not
# required on /home or /var (users/services need to execute their own files
# there); the set below is the explicit per-mount list, not a uniform
# 3-per-mount grid.
_MOUNT_OPTION_CANDIDATES = [
    ("mount_dev_shm_nodev", "/dev/shm", "nodev"),
    ("mount_dev_shm_nosuid", "/dev/shm", "nosuid"),
    ("mount_dev_shm_noexec", "/dev/shm", "noexec"),
    ("mount_home_nodev", "/home", "nodev"),
    ("mount_home_nosuid", "/home", "nosuid"),
    ("mount_tmp_nodev", "/tmp", "nodev"),
    ("mount_tmp_nosuid", "/tmp", "nosuid"),
    ("mount_tmp_noexec", "/tmp", "noexec"),
    ("mount_var_nodev", "/var", "nodev"),
    ("mount_var_nosuid", "/var", "nosuid"),
    ("mount_var_log_nodev", "/var/log", "nodev"),
    ("mount_var_log_nosuid", "/var/log", "nosuid"),
    ("mount_var_log_noexec", "/var/log", "noexec"),
    ("mount_var_log_audit_nodev", "/var/log/audit", "nodev"),
    ("mount_var_log_audit_nosuid", "/var/log/audit", "nosuid"),
    ("mount_var_log_audit_noexec", "/var/log/audit", "noexec"),
    ("mount_var_tmp_nodev", "/var/tmp", "nodev"),
    ("mount_var_tmp_nosuid", "/var/tmp", "nosuid"),
    ("mount_var_tmp_noexec", "/var/tmp", "noexec"),
]


def _evaluate_separate_partition(facts: SystemFacts, target: str) -> bool:
    """<target> has to actually be its own mount, distinct from the root
    filesystem. Unlike the option checks above, this one is unconditional.
    """
    return target in parse_mounts(facts.mounts_text)


def _evidence_separate_partition(facts: SystemFacts, target: str) -> str:
    mounts = parse_mounts(facts.mounts_text)
    if target in mounts:
        return f"{target}: separate mount, options = {mounts[target]}"
    return f"{target}: not a separate mount"


def _separate_partition_check(check_id: str, target: str) -> "Check":
    return Check(
        id=check_id,
        evaluate=lambda facts, t=target: _evaluate_separate_partition(facts, t),
        evidence=lambda facts, t=target: _evidence_separate_partition(facts, t),
    )


# 7 candidates: 5 generic "separate partition for <mount>" targets plus /tmp
# and /dev/shm; they all check the exact same thing.
_SEPARATE_PARTITION_CANDIDATES = [
    ("mount_tmp_separate", "/tmp"),
    ("mount_dev_shm_separate", "/dev/shm"),
    ("mount_home_separate", "/home"),
    ("mount_var_separate", "/var"),
    ("mount_var_log_separate", "/var/log"),
    ("mount_var_log_audit_separate", "/var/log/audit"),
    ("mount_var_tmp_separate", "/var/tmp"),
]


# Matches a plain PAM "password ... pam_pwquality.so ... enforcing=0" line.
# re.search rather than a full-line re.match, since only the offending token
# matters.
_PWQUALITY_ENFORCING_ZERO_RE = re.compile(
    r"^\s*password\s+\S+\s+pam_pwquality\.so\b.*\benforcing=0\b", re.IGNORECASE | re.MULTILINE
)


def _evaluate_pwquality_enforcing(facts: SystemFacts) -> bool:
    """`enforcing=0` must not be set in /etc/security/pwquality.conf or
    /etc/security/pwquality.conf.d/*.conf, and the pam_pwquality.so line in
    /etc/pam.d/common-password must not carry enforcing=0 as an argument
    either. The secure default is `enforcing` left unset (or 1) in both
    places -- distinct from the "enforce_for_root" check, a different
    directive.
    """
    directives = parse_pwquality_conf(facts.pwquality_text)
    if directives.get("enforcing") == "0":
        return False
    return _PWQUALITY_ENFORCING_ZERO_RE.search(facts.pam_common_password) is None


def _evidence_pwquality_enforcing(facts: SystemFacts) -> str:
    directives = parse_pwquality_conf(facts.pwquality_text)
    conf_value = directives.get("enforcing", "<not set>")
    pam_hit = _PWQUALITY_ENFORCING_ZERO_RE.search(facts.pam_common_password) is not None
    return f"pwquality.conf: enforcing={conf_value}; common-password pam_pwquality.so enforcing=0: {pam_hit}"


# Group U: the auditd.conf family -- auditd.conf directive checks, plus
# mode/owner checks over the config files, the audit log directory + its
# files, and a fixed set of audit tool binaries. All backed by the single
# facts.audit_conf_text field (see facts.py's comment there, including the
# audit-tools list difference between target documents that this group works
# around).
_AUDIT_CONF_CONFFILES_MARKER = "---CONFFILES---"
_AUDIT_CONF_LOGDIR_MARKER = "---LOGDIR---"
_AUDIT_CONF_LOGFILES_MARKER = "---LOGFILES---"
_AUDIT_CONF_TOOLS_MARKER = "---TOOLS---"


def _audit_conf_sections(text: str) -> tuple[str, str, str, str, str]:
    """Splits facts.audit_conf_text into (auditd.conf directive text,
    config-file stat lines, log-directory stat line, log-file stat lines,
    audit-tool stat lines) -- see facts.py's comment on that field for the
    shell command that produces it.
    """
    i1 = text.find(_AUDIT_CONF_CONFFILES_MARKER)
    i2 = text.find(_AUDIT_CONF_LOGDIR_MARKER)
    i3 = text.find(_AUDIT_CONF_LOGFILES_MARKER)
    i4 = text.find(_AUDIT_CONF_TOOLS_MARKER)
    if -1 in (i1, i2, i3, i4):
        return text, "", "", "", ""
    return (
        text[:i1],
        text[i1 + len(_AUDIT_CONF_CONFFILES_MARKER) : i2],
        text[i2 + len(_AUDIT_CONF_LOGDIR_MARKER) : i3],
        text[i3 + len(_AUDIT_CONF_LOGFILES_MARKER) : i4],
        text[i4 + len(_AUDIT_CONF_TOOLS_MARKER) :],
    )


def _audit_directives(facts: SystemFacts) -> dict[str, str]:
    """auditd.conf is the same "key = value" shape as pwquality.conf/
    pwhistory.conf, so parse_pwquality_conf() (defined above) already does
    exactly what's needed here -- no new parser.
    """
    conf_text, _, _, _, _ = _audit_conf_sections(facts.audit_conf_text)
    return parse_pwquality_conf(conf_text)


def _parse_stat_lines(text: str) -> list[dict[str, str]]:
    """Parses "mode=<octal> uid=<n> gid=<n> gname=<name> path=<path>" lines
    -- the one line shape facts.audit_conf_text uses for every stat/find
    section (config files, log directory, log files, tools), so this one
    parser covers all of them. Lines that didn't produce a mode (a stat/find
    error, e.g. a missing tool binary) are skipped -- same "missing means no
    entry" posture as facts.file_stats.
    """
    entries = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        fields = dict(tok.split("=", 1) for tok in line.split() if "=" in tok)
        if "mode" in fields:
            entries.append(fields)
    return entries


def _mode_mask_ok(fields: dict[str, str], perm_mask: int) -> bool:
    """True if none of perm_mask's bits are set in the entry's mode (e.g. 0137 for
    "mode 640 or more restrictive", 0027 for "750 or more restrictive", 0022 for
    "755 or more restrictive").
    """
    try:
        return (int(fields["mode"], 8) & perm_mask) == 0
    except (KeyError, ValueError):
        return False


def _evaluate_audit_conf_files_mode(facts: SystemFacts) -> bool:
    """Every file under /etc/audit/ named *.conf or *.rules must have a mode with
    none of 0137 set (mode 640 or more restrictive). No /etc/audit/ at all
    (auditd not installed) is a vacuous PASS.
    """
    _, conffiles_text, _, _, _ = _audit_conf_sections(facts.audit_conf_text)
    return all(_mode_mask_ok(f, 0o137) for f in _parse_stat_lines(conffiles_text))


def _evidence_audit_conf_files_mode(facts: SystemFacts) -> str:
    _, conffiles_text, _, _, _ = _audit_conf_sections(facts.audit_conf_text)
    entries = _parse_stat_lines(conffiles_text)
    bad = [f"{f.get('path')}(mode={f.get('mode')})" for f in entries if not _mode_mask_ok(f, 0o137)]
    if not entries:
        return "/etc/audit/: no *.conf/*.rules files found"
    if bad:
        return "/etc/audit/ files not mode 0640 or stricter: " + ", ".join(bad)
    return f"/etc/audit/: all {len(entries)} *.conf/*.rules files are mode 0640 or stricter"


def _evaluate_audit_log_files_group_owner(facts: SystemFacts) -> bool:
    """`log_group` in auditd.conf must be adm or root (an unset directive is
    auditd's own root-group default, a vacuous PASS, same posture as every
    other unset-directive-at-its-secure-default check in this module), AND
    every file in the audit log directory (dirname of `log_file`) must be
    group-owned by root or adm. Same fail-closed-on-missing-directory posture
    as the mode/owner checks below.
    """
    log_group = _audit_directives(facts).get("log_group")
    if log_group is not None and log_group.strip().lower() not in ("adm", "root"):
        return False
    _, _, logdir_text, logfiles_text, _ = _audit_conf_sections(facts.audit_conf_text)
    if not _parse_stat_lines(logdir_text):
        return False
    return all(f.get("gname") in ("root", "adm") for f in _parse_stat_lines(logfiles_text))


def _evidence_audit_log_files_group_owner(facts: SystemFacts) -> str:
    log_group = _audit_directives(facts).get("log_group", "<not set>")
    _, _, logdir_text, logfiles_text, _ = _audit_conf_sections(facts.audit_conf_text)
    if not _parse_stat_lines(logdir_text):
        return f"auditd.conf: log_group {log_group}; audit log directory: not found (check auditd.conf's log_file)"
    entries = _parse_stat_lines(logfiles_text)
    bad = [f"{f.get('path')}(group={f.get('gname')})" for f in entries if f.get("gname") not in ("root", "adm")]
    parts = [f"auditd.conf: log_group {log_group}"]
    parts.append("bad log file groups: " + ", ".join(bad) if bad else f"{len(entries)} log file(s) group root/adm")
    return "; ".join(parts)


def _evaluate_audit_log_files_mode(facts: SystemFacts) -> bool:
    """Every file in the audit log directory (dirname of `log_file` in
    auditd.conf) must have a mode with none of 0137 set (mode 640 or more
    restrictive). Unlike the config-files check above, a missing auditd.conf
    or log directory is an explicit FAIL, not a vacuous pass.
    """
    _, _, logdir_text, logfiles_text, _ = _audit_conf_sections(facts.audit_conf_text)
    if not _parse_stat_lines(logdir_text):
        return False
    return all(_mode_mask_ok(f, 0o137) for f in _parse_stat_lines(logfiles_text))


def _evidence_audit_log_files_mode(facts: SystemFacts) -> str:
    _, _, logdir_text, logfiles_text, _ = _audit_conf_sections(facts.audit_conf_text)
    if not _parse_stat_lines(logdir_text):
        return "audit log directory: not found (check auditd.conf's log_file)"
    entries = _parse_stat_lines(logfiles_text)
    bad = [f"{f.get('path')}(mode={f.get('mode')})" for f in entries if not _mode_mask_ok(f, 0o137)]
    if bad:
        return "audit log files not mode 0640 or stricter: " + ", ".join(bad)
    return f"audit log directory: all {len(entries)} file(s) are mode 0640 or stricter"


def _evaluate_audit_log_files_owner(facts: SystemFacts) -> bool:
    """Every file in the audit log directory must be owned by root. Same
    fail-closed-on-missing-directory posture as the mode check above.
    """
    _, _, logdir_text, logfiles_text, _ = _audit_conf_sections(facts.audit_conf_text)
    if not _parse_stat_lines(logdir_text):
        return False
    return all(f.get("uid") == "0" for f in _parse_stat_lines(logfiles_text))


def _evidence_audit_log_files_owner(facts: SystemFacts) -> str:
    _, _, logdir_text, logfiles_text, _ = _audit_conf_sections(facts.audit_conf_text)
    if not _parse_stat_lines(logdir_text):
        return "audit log directory: not found (check auditd.conf's log_file)"
    entries = _parse_stat_lines(logfiles_text)
    bad = [f"{f.get('path')}(uid={f.get('uid')})" for f in entries if f.get("uid") != "0"]
    if bad:
        return "audit log files not owned by root: " + ", ".join(bad)
    return f"audit log directory: all {len(entries)} file(s) owned by root"


def _evaluate_audit_log_storage_size(facts: SystemFacts) -> bool:
    """`max_log_file` in auditd.conf must be present and numeric; any value is
    acceptable (site-policy-defined).
    """
    value = _audit_directives(facts).get("max_log_file")
    return value is not None and value.strip().isdigit()


def _evidence_audit_log_storage_size(facts: SystemFacts) -> str:
    value = _audit_directives(facts).get("max_log_file", "<not set>")
    return f"auditd.conf: max_log_file {value}"


def _evaluate_audit_logs_not_auto_deleted(facts: SystemFacts) -> bool:
    """`max_log_file_action` in auditd.conf must be `keep_logs`."""
    return _audit_directives(facts).get("max_log_file_action", "").strip().lower() == "keep_logs"


def _evidence_audit_logs_not_auto_deleted(facts: SystemFacts) -> str:
    value = _audit_directives(facts).get("max_log_file_action", "<not set>")
    return f"auditd.conf: max_log_file_action {value}"


def _evaluate_audit_tools_mode(facts: SystemFacts) -> bool:
    """Every audit tool's mode must have none of 0022 set (mode 755 or more
    restrictive), checked uniformly over all 6 tools facts.py collects (one
    supported document lists only 5, without /sbin/autrace -- see facts.py's
    comment on audit_conf_text).
    """
    _, _, _, _, tools_text = _audit_conf_sections(facts.audit_conf_text)
    entries = _parse_stat_lines(tools_text)
    return len(entries) > 0 and all(_mode_mask_ok(f, 0o022) for f in entries)


def _evidence_audit_tools_mode(facts: SystemFacts) -> str:
    _, _, _, _, tools_text = _audit_conf_sections(facts.audit_conf_text)
    entries = _parse_stat_lines(tools_text)
    if not entries:
        return "audit tools: could not stat any of auditctl/aureport/ausearch/auditd/augenrules/autrace"
    bad = [f"{f.get('path')}(mode={f.get('mode')})" for f in entries if not _mode_mask_ok(f, 0o022)]
    if bad:
        return "audit tools not mode 0755 or stricter: " + ", ".join(bad)
    return f"audit tools: all {len(entries)} checked binaries are mode 0755 or stricter"


_DISK_FULL_ACTIONS = ("halt", "single")
_DISK_ERROR_ACTIONS = ("syslog", "single", "halt")


def _evaluate_audit_disk_full_error_actions(facts: SystemFacts) -> bool:
    """`disk_full_action` must be halt or single, AND `disk_error_action` must be
    syslog, single, or halt.
    """
    directives = _audit_directives(facts)
    return (
        directives.get("disk_full_action", "").strip().lower() in _DISK_FULL_ACTIONS
        and directives.get("disk_error_action", "").strip().lower() in _DISK_ERROR_ACTIONS
    )


def _evidence_audit_disk_full_error_actions(facts: SystemFacts) -> str:
    directives = _audit_directives(facts)
    full = directives.get("disk_full_action", "<not set>")
    error = directives.get("disk_error_action", "<not set>")
    return f"auditd.conf: disk_full_action {full}, disk_error_action {error}"


_SPACE_LEFT_ACTIONS = ("email", "exec", "single", "halt")
_ADMIN_SPACE_LEFT_ACTIONS = ("single", "halt")


def _evaluate_audit_space_left_actions(facts: SystemFacts) -> bool:
    """`space_left_action` must be email, exec, single, or halt, AND
    `admin_space_left_action` must be single or halt.
    """
    directives = _audit_directives(facts)
    return (
        directives.get("space_left_action", "").strip().lower() in _SPACE_LEFT_ACTIONS
        and directives.get("admin_space_left_action", "").strip().lower() in _ADMIN_SPACE_LEFT_ACTIONS
    )


def _evidence_audit_space_left_actions(facts: SystemFacts) -> str:
    directives = _audit_directives(facts)
    space = directives.get("space_left_action", "<not set>")
    admin = directives.get("admin_space_left_action", "<not set>")
    return f"auditd.conf: space_left_action {space}, admin_space_left_action {admin}"


def _evaluate_audit_log_dir_mode(facts: SystemFacts) -> bool:
    """The audit log directory (dirname of `log_file` in auditd.conf) must have a
    mode with none of 0027 set (mode 750 or more restrictive). A missing
    auditd.conf or log directory is an explicit FAIL, not a vacuous pass.
    """
    _, _, logdir_text, _, _ = _audit_conf_sections(facts.audit_conf_text)
    entries = _parse_stat_lines(logdir_text)
    return len(entries) == 1 and _mode_mask_ok(entries[0], 0o027)


def _evidence_audit_log_dir_mode(facts: SystemFacts) -> str:
    _, _, logdir_text, _, _ = _audit_conf_sections(facts.audit_conf_text)
    entries = _parse_stat_lines(logdir_text)
    if not entries:
        return "audit log directory: not found (check auditd.conf's log_file)"
    f = entries[0]
    return f"audit log directory {f.get('path')}: mode={f.get('mode')}"


@dataclass
class Check:
    """One implemented, hand-written evaluator, identified by a stable `id`
    of our own (snake_case, never reused or renamed; tests/snapshots/
    check_ids.txt guards that). The consumer (invariant_api) maps the id to
    whichever control it corresponds to in each document.

    `family` groups checks by the OS family they were written against
    (systemd/shadow/shell tooling shape), so `run_assessment()` can filter
    CHECKS down to only the ones applicable to a given target instead of
    running every check against every OS unconditionally. Defaults to
    "debian_ubuntu", the one real family that exists today -- see
    `family_for_os()` below for the os_id -> family mapping.
    """

    id: str
    evaluate: Callable[[SystemFacts], bool]
    evidence: Callable[[SystemFacts], str]
    family: str = "debian_ubuntu"


# The only checks Invariant actually knows how to run right now.
# Adding another means writing its evaluate()/evidence() by hand, the same
# way these were -- extending facts.SystemFacts first if it needs a new
# kind of collected data.
CHECKS = [
    Check(
        id="ssh_permit_root_login",
        evaluate=_evaluate_ssh_permit_root_login,
        evidence=_evidence_ssh_permit_root_login,
    ),
    Check(
        id="etc_shadow_permissions",
        evaluate=_evaluate_etc_shadow_permissions,
        evidence=_evidence_etc_shadow_permissions,
    ),
    Check(
        id="ssh_permit_user_environment",
        evaluate=_evaluate_ssh_permit_user_environment,
        evidence=_evidence_ssh_permit_user_environment,
    ),
    Check(
        id="ssh_ignore_rhosts",
        evaluate=_evaluate_ssh_ignore_rhosts,
        evidence=_evidence_ssh_ignore_rhosts,
    ),
    Check(
        id="ssh_login_grace_time",
        evaluate=_evaluate_ssh_login_grace_time,
        evidence=_evidence_ssh_login_grace_time,
    ),
    # Group A: plain file-permission checks. Permission checks for hosts.allow/hosts.deny were
    # looked at and not implemented -- see module docstring notes below the
    # CHECKS list.
    Check(
        id="etc_issue_permissions",
        evaluate=_evaluate_etc_issue_permissions,
        evidence=_evidence_etc_issue_permissions,
    ),
    Check(
        id="etc_issue_net_permissions",
        evaluate=_evaluate_etc_issue_net_permissions,
        evidence=_evidence_etc_issue_net_permissions,
    ),
    Check(
        id="etc_passwd_permissions",
        evaluate=_evaluate_etc_passwd_permissions,
        evidence=_evidence_etc_passwd_permissions,
    ),
    Check(
        id="etc_passwd_minus_permissions",
        evaluate=_evaluate_etc_passwd_minus_permissions,
        evidence=_evidence_etc_passwd_minus_permissions,
    ),
    Check(
        id="etc_group_permissions",
        evaluate=_evaluate_etc_group_permissions,
        evidence=_evidence_etc_group_permissions,
    ),
    Check(
        id="etc_group_minus_permissions",
        evaluate=_evaluate_etc_group_minus_permissions,
        evidence=_evidence_etc_group_minus_permissions,
    ),
    Check(
        id="etc_shadow_minus_permissions",
        evaluate=_evaluate_etc_shadow_minus_permissions,
        evidence=_evidence_etc_shadow_minus_permissions,
    ),
    Check(
        id="etc_gshadow_permissions",
        evaluate=_evaluate_etc_gshadow_permissions,
        evidence=_evidence_etc_gshadow_permissions,
    ),
    Check(
        id="etc_gshadow_minus_permissions",
        evaluate=_evaluate_etc_gshadow_minus_permissions,
        evidence=_evidence_etc_gshadow_minus_permissions,
    ),
    Check(
        id="etc_shells_permissions",
        evaluate=_evaluate_etc_shells_permissions,
        evidence=_evidence_etc_shells_permissions,
    ),
    Check(
        id="etc_ssh_sshd_config_permissions",
        evaluate=_evaluate_etc_ssh_sshd_config_permissions,
        evidence=_evidence_etc_ssh_sshd_config_permissions,
    ),
    # Group B: passwd/group/shadow content checks.
    Check(
        id="shadow_password_fields_not_empty",
        evaluate=_evaluate_shadow_password_fields_not_empty,
        evidence=_evidence_shadow_password_fields_not_empty,
    ),
    Check(
        id="passwd_accounts_use_shadowed_passwords",
        evaluate=_evaluate_passwd_accounts_use_shadowed_passwords,
        evidence=_evidence_passwd_accounts_use_shadowed_passwords,
    ),
    Check(
        id="root_only_gid0_account",
        evaluate=_evaluate_root_only_gid0_account,
        evidence=_evidence_root_only_gid0_account,
    ),
    Check(
        id="root_only_uid0_account",
        evaluate=_evaluate_root_only_uid0_account,
        evidence=_evidence_root_only_uid0_account,
    ),
    Check(
        id="root_only_gid0_group",
        evaluate=_evaluate_root_only_gid0_group,
        evidence=_evidence_root_only_gid0_group,
    ),
    # Group C: PAM + login.defs checks.
    Check(
        id="pam_faillock_enabled",
        evaluate=_evaluate_pam_faillock_enabled,
        evidence=_evidence_pam_faillock_enabled,
    ),
    Check(
        id="pam_pwquality_enabled",
        evaluate=_evaluate_pam_pwquality_enabled,
        evidence=_evidence_pam_pwquality_enabled,
    ),
    Check(
        id="pam_pwhistory_enabled",
        evaluate=_evaluate_pam_pwhistory_enabled,
        evidence=_evidence_pam_pwhistory_enabled,
    ),
    Check(
        # nullok on a pam_unix.so line.
        id="pam_no_nullok",
        evaluate=_evaluate_pam_no_nullok,
        evidence=_evidence_pam_no_nullok,
    ),
    Check(
        # The strictest umask wording only exists in a document family that
        # document_slug_for_os() never resolves to, so this check uses the wording
        # present in every supported document, at a 027-or-more-restrictive
        # threshold.
        id="default_umask",
        evaluate=_evaluate_default_umask,
        evidence=_evidence_default_umask,
    ),
    # Group G: password quality/history, via pwquality.conf and pwhistory.conf.
    Check(
        id="pwquality_enforce_for_root",
        evaluate=_evaluate_pwquality_enforce_for_root,
        evidence=_evidence_pwquality_enforce_for_root,
    ),
    Check(
        id="pwquality_minlen",
        evaluate=_evaluate_pwquality_minlen,
        evidence=_evidence_pwquality_minlen,
    ),
    Check(
        id="pwquality_complexity",
        evaluate=_evaluate_pwquality_complexity,
        evidence=_evidence_pwquality_complexity,
    ),
    Check(
        id="pwquality_max_repeat",
        evaluate=_evaluate_pwquality_max_repeat,
        evidence=_evidence_pwquality_max_repeat,
    ),
    Check(
        id="pwquality_max_sequence",
        evaluate=_evaluate_pwquality_max_sequence,
        evidence=_evidence_pwquality_max_sequence,
    ),
    Check(
        id="pwquality_difok",
        evaluate=_evaluate_pwquality_difok,
        evidence=_evidence_pwquality_difok,
    ),
    Check(
        id="pwhistory_remember",
        evaluate=_evaluate_pwhistory_remember,
        evidence=_evidence_pwhistory_remember,
    ),
    Check(
        id="pwhistory_enforce_for_root",
        evaluate=_evaluate_pwhistory_enforce_for_root,
        evidence=_evidence_pwhistory_enforce_for_root,
    ),
    # Group H: pam_faillock lockout policy, via faillock.conf +
    # pam_faillock.so's own inline arguments on common-auth.
    Check(
        id="faillock_unlock_time",
        evaluate=_evaluate_faillock_unlock_time,
        evidence=_evidence_faillock_unlock_time,
    ),
    Check(
        id="faillock_deny",
        evaluate=_evaluate_faillock_deny,
        evidence=_evidence_faillock_deny,
    ),
    Check(
        id="faillock_root_lockout",
        evaluate=_evaluate_faillock_root_lockout,
        evidence=_evidence_faillock_root_lockout,
    ),
    # Group D: remaining sshd_config directives + SSH host key permissions.
    Check(
        id="ssh_max_sessions",
        evaluate=_evaluate_ssh_max_sessions,
        evidence=_evidence_ssh_max_sessions,
    ),
    Check(
        id="ssh_log_level",
        evaluate=_evaluate_ssh_log_level,
        evidence=_evidence_ssh_log_level,
    ),
    Check(
        id="ssh_use_pam",
        evaluate=_evaluate_ssh_use_pam,
        evidence=_evidence_ssh_use_pam,
    ),
    Check(
        id="ssh_disable_forwarding",
        evaluate=_evaluate_ssh_disable_forwarding,
        evidence=_evidence_ssh_disable_forwarding,
    ),
    Check(
        id="ssh_ciphers",
        evaluate=_evaluate_ssh_ciphers,
        evidence=_evidence_ssh_ciphers,
    ),
    Check(
        id="ssh_kex_algorithms",
        evaluate=_evaluate_ssh_kex_algorithms,
        evidence=_evidence_ssh_kex_algorithms,
    ),
    Check(
        id="ssh_private_host_key_permissions",
        evaluate=_evaluate_ssh_private_host_key_permissions,
        evidence=_evidence_ssh_private_host_key_permissions,
    ),
    Check(
        id="ssh_public_host_key_permissions",
        evaluate=_evaluate_ssh_public_host_key_permissions,
        evidence=_evidence_ssh_public_host_key_permissions,
    ),
    Check(
        id="ldap_client_not_installed",
        evaluate=_evaluate_ldap_client_not_installed,
        evidence=_evidence_ldap_client_not_installed,
    ),
    Check(
        id="nis_client_not_installed",
        evaluate=_evaluate_nis_client_not_installed,
        evidence=_evidence_nis_client_not_installed,
    ),
    Check(
        id="xinetd_not_installed",
        evaluate=_evaluate_xinetd_not_installed,
        evidence=_evidence_xinetd_not_installed,
    ),
    Check(
        id="rsync_not_installed",
        evaluate=_evaluate_rsync_not_installed,
        evidence=_evidence_rsync_not_installed,
    ),
    Check(
        id="x_window_not_installed",
        evaluate=_evaluate_x_window_not_installed,
        evidence=_evidence_x_window_not_installed,
    ),
    Check(
        id="telnet_client_not_installed",
        evaluate=_evaluate_telnet_client_not_installed,
        evidence=_evidence_telnet_client_not_installed,
    ),
    Check(
        id="rsh_client_not_installed",
        evaluate=_evaluate_rsh_client_not_installed,
        evidence=_evidence_rsh_client_not_installed,
    ),
    Check(
        id="ftp_client_not_installed",
        evaluate=_evaluate_ftp_client_not_installed,
        evidence=_evidence_ftp_client_not_installed,
    ),
    Check(
        id="talk_client_not_installed",
        evaluate=_evaluate_talk_client_not_installed,
        evidence=_evidence_talk_client_not_installed,
    ),
    Check(
        id="prelink_not_installed",
        evaluate=_evaluate_prelink_not_installed,
        evidence=_evidence_prelink_not_installed,
    ),
    # Group I: auditd config/tooling file ownership + rules immutability. Two further candidates were looked at and not
    # implemented:
    #   - an audit-configuration-loaded-regardless-of-errors check, which only
    #     exists in one supported document;
    #   - a SUID/SGID review check, which only lists files for a human to review
    #     and has no pass/fail condition.
    Check(
        id="audit_conf_files_owner",
        evaluate=_evaluate_audit_conf_files_owner,
        evidence=_evidence_audit_conf_files_owner,
    ),
    Check(
        id="audit_conf_files_group_owner",
        evaluate=_evaluate_audit_conf_files_group_owner,
        evidence=_evidence_audit_conf_files_group_owner,
    ),
    Check(
        id="audit_tools_owner",
        evaluate=_evaluate_audit_tools_owner,
        evidence=_evidence_audit_tools_owner,
    ),
    Check(
        id="audit_tools_group_owner",
        evaluate=_evaluate_audit_tools_group_owner,
        evidence=_evidence_audit_tools_group_owner,
    ),
    Check(
        id="audit_config_immutable",
        evaluate=_evaluate_audit_config_immutable,
        evidence=_evidence_audit_config_immutable,
    ),
    # Group H: sudoers + cron file permissions.
    Check(
        id="sudo_log_file_exists",
        evaluate=_evaluate_sudo_log_file_exists,
        evidence=_evidence_sudo_log_file_exists,
    ),
    Check(
        # NOPASSWD in sudoers.
        id="sudo_no_nopasswd",
        evaluate=_evaluate_sudo_no_nopasswd,
        evidence=_evidence_sudo_no_nopasswd,
    ),
    Check(
        id="sudo_reauthentication_required",
        evaluate=_evaluate_sudo_reauthentication_required,
        evidence=_evidence_sudo_reauthentication_required,
    ),
    # A sudo authentication timeout check was looked at and not implemented: one
    # supported document describes it only via `sudo -V` output, with no static
    # config fallback, and facts.py deliberately never runs config-independent
    # live commands like `sudo -V`, so it can't be resolved correctly for every
    # supported document.
    Check(
        id="etc_crontab_permissions",
        evaluate=_evaluate_etc_crontab_permissions,
        evidence=_evidence_etc_crontab_permissions,
    ),
    Check(
        id="cron_hourly_permissions",
        evaluate=_evaluate_cron_hourly_permissions,
        evidence=_evidence_cron_hourly_permissions,
    ),
    Check(
        id="cron_daily_permissions",
        evaluate=_evaluate_cron_daily_permissions,
        evidence=_evidence_cron_daily_permissions,
    ),
    Check(
        id="cron_weekly_permissions",
        evaluate=_evaluate_cron_weekly_permissions,
        evidence=_evidence_cron_weekly_permissions,
    ),
    Check(
        id="cron_monthly_permissions",
        evaluate=_evaluate_cron_monthly_permissions,
        evidence=_evidence_cron_monthly_permissions,
    ),
    Check(
        # See test_assess_target.py's _SYSTEMIC_GAPS handling for where the
        # per-document differences matter.
        id="cron_d_permissions",
        evaluate=_evaluate_cron_d_permissions,
        evidence=_evidence_cron_d_permissions,
    ),
    # Group J: journald config + a few standalone file checks. rsyslog checks
    # were not implemented: the oldest supported Debian document has no
    # rsyslog-related controls at all, so none could resolve across every
    # supported document -- see the module docstring notes below CHECKS.
    Check(
        id="journald_compress",
        evaluate=_evaluate_journald_compress,
        evidence=_evidence_journald_compress,
    ),
    Check(
        id="journald_storage",
        evaluate=_evaluate_journald_storage,
        evidence=_evidence_journald_storage,
    ),
    Check(
        id="journald_log_rotation",
        evaluate=_evaluate_journald_log_rotation,
        evidence=_evidence_journald_log_rotation,
    ),
    Check(
        id="shells_no_nologin",
        evaluate=_evaluate_shells_no_nologin,
        evidence=_evidence_shells_no_nologin,
    ),
    Check(
        id="etc_motd_permissions",
        evaluate=_evaluate_etc_motd_permissions,
        evidence=_evidence_etc_motd_permissions,
    ),
    Check(
        id="bootloader_config_permissions",
        evaluate=_evaluate_bootloader_config_permissions,
        evidence=_evidence_bootloader_config_permissions,
    ),
    # Group F: remaining sshd_config directives + PAM/login.defs checks. One
    # candidate (root account access control) was not implemented: the oldest
    # supported Debian document's nearest equivalent is a stricter, only
    # partially overlapping condition, so merging the checks would silently
    # loosen that document's pass condition. (The root umask candidate is
    # implemented in Group K below, once facts.py grew the
    # root_shell_startup_text field.)
    Check(
        id="ssh_macs",
        evaluate=_evaluate_ssh_macs,
        evidence=_evidence_ssh_macs,
    ),
    Check(
        id="ssh_max_startups",
        evaluate=_evaluate_ssh_max_startups,
        evidence=_evidence_ssh_max_startups,
    ),
    Check(
        id="login_defs_encrypt_method",
        evaluate=_evaluate_login_defs_encrypt_method,
        evidence=_evidence_login_defs_encrypt_method,
    ),
    Check(
        id="pam_unix_enabled",
        evaluate=_evaluate_pam_unix_enabled,
        evidence=_evidence_pam_unix_enabled,
    ),
    Check(
        id="pam_unix_no_remember",
        evaluate=_evaluate_pam_unix_no_remember,
        evidence=_evidence_pam_unix_no_remember,
    ),
    Check(
        id="pam_unix_strong_password_hashing",
        evaluate=_evaluate_pam_unix_strong_password_hashing,
        evidence=_evidence_pam_unix_strong_password_hashing,
    ),
    Check(
        id="pam_unix_use_authtok",
        evaluate=_evaluate_pam_unix_use_authtok,
        evidence=_evidence_pam_unix_use_authtok,
    ),
    Check(
        id="pam_pwhistory_use_authtok",
        evaluate=_evaluate_pam_pwhistory_use_authtok,
        evidence=_evidence_pam_pwhistory_use_authtok,
    ),
    # Group K: package presence (installed_packages must contain the package,
    # the inverse of the "not installed" checks in the block above). Candidates
    # for rsyslog and rsyslog-gnutls were not implemented: they don't resolve on
    # the oldest supported documents, consistent with the Group J note above.
    # The ufw check resolves on every supported document.
    Check(
        id="ufw_installed",
        evaluate=_evaluate_ufw_installed,
        evidence=_evidence_ufw_installed,
    ),
    # Group L: sshd_config directives (round 2). No candidates dropped this round.
    Check(
        id="ssh_max_auth_tries",
        evaluate=_evaluate_ssh_max_auth_tries,
        evidence=_evidence_ssh_max_auth_tries,
    ),
    Check(
        id="ssh_permit_empty_passwords",
        evaluate=_evaluate_ssh_permit_empty_passwords,
        evidence=_evidence_ssh_permit_empty_passwords,
    ),
    Check(
        id="ssh_hostbased_authentication",
        evaluate=_evaluate_ssh_hostbased_authentication,
        evidence=_evidence_ssh_hostbased_authentication,
    ),
    Check(
        id="ssh_gssapi_authentication",
        evaluate=_evaluate_ssh_gssapi_authentication,
        evidence=_evidence_ssh_gssapi_authentication,
    ),
    Check(
        id="ssh_client_alive",
        evaluate=_evaluate_ssh_client_alive,
        evidence=_evidence_ssh_client_alive,
    ),
    Check(
        # Partial check -- see _evaluate_ssh_banner's docstring: the banner-file
        # content isn't verified, only that Banner points at an absolute path.
        id="ssh_banner",
        evaluate=_evaluate_ssh_banner,
        evidence=_evidence_ssh_banner,
    ),
    Check(
        # Directive-presence only -- the actual user/group list is site policy, same
        # as this project's other "configured, not judged" checks.
        id="ssh_allow_deny_configured",
        evaluate=_evaluate_ssh_allow_deny_configured,
        evidence=_evidence_ssh_allow_deny_configured,
    ),
    # Group M: unused network service packages, batch A (round 2).
    Check(
        id="avahi_not_installed",
        evaluate=_evaluate_avahi_not_installed,
        evidence=_evidence_avahi_not_installed,
    ),
    Check(
        id="bluetooth_not_installed",
        evaluate=_evaluate_bluetooth_not_installed,
        evidence=_evidence_bluetooth_not_installed,
    ),
    Check(
        id="dhcp_server_not_installed",
        evaluate=_evaluate_dhcp_server_not_installed,
        evidence=_evidence_dhcp_server_not_installed,
    ),
    Check(
        id="dns_server_not_installed",
        evaluate=_evaluate_dns_server_not_installed,
        evidence=_evidence_dns_server_not_installed,
    ),
    Check(
        id="dnsmasq_not_installed",
        evaluate=_evaluate_dnsmasq_not_installed,
        evidence=_evidence_dnsmasq_not_installed,
    ),
    Check(
        id="ftp_server_not_installed",
        evaluate=_evaluate_ftp_server_not_installed,
        evidence=_evidence_ftp_server_not_installed,
    ),
    Check(
        id="ldap_server_not_installed",
        evaluate=_evaluate_ldap_server_not_installed,
        evidence=_evidence_ldap_server_not_installed,
    ),
    Check(
        id="message_access_server_not_installed",
        evaluate=_evaluate_message_access_server_not_installed,
        evidence=_evidence_message_access_server_not_installed,
    ),
    Check(
        id="nfs_server_not_installed",
        evaluate=_evaluate_nfs_server_not_installed,
        evidence=_evidence_nfs_server_not_installed,
    ),
    Check(
        id="nis_server_not_installed",
        evaluate=_evaluate_nis_server_not_installed,
        evidence=_evidence_nis_server_not_installed,
    ),
    # Group N: unused network service packages batch B + required packages (round 2)
    Check(
        id="cups_not_installed",
        evaluate=_evaluate_cups_not_installed,
        evidence=_evidence_cups_not_installed,
    ),
    Check(
        id="rpcbind_not_installed",
        evaluate=_evaluate_rpcbind_not_installed,
        evidence=_evidence_rpcbind_not_installed,
    ),
    Check(
        id="samba_not_installed",
        evaluate=_evaluate_samba_not_installed,
        evidence=_evidence_samba_not_installed,
    ),
    Check(
        id="snmp_not_installed",
        evaluate=_evaluate_snmp_not_installed,
        evidence=_evidence_snmp_not_installed,
    ),
    Check(
        id="tftp_server_not_installed",
        evaluate=_evaluate_tftp_server_not_installed,
        evidence=_evidence_tftp_server_not_installed,
    ),
    Check(
        id="web_proxy_not_installed",
        evaluate=_evaluate_web_proxy_not_installed,
        evidence=_evidence_web_proxy_not_installed,
    ),
    Check(
        id="web_server_not_installed",
        evaluate=_evaluate_web_server_not_installed,
        evidence=_evidence_web_server_not_installed,
    ),
    Check(
        id="autofs_not_installed",
        evaluate=_evaluate_autofs_not_installed,
        evidence=_evidence_autofs_not_installed,
    ),
    Check(
        id="sudo_installed",
        evaluate=_evaluate_sudo_installed,
        evidence=_evidence_sudo_installed,
    ),
    Check(
        id="auditd_packages_installed",
        evaluate=_evaluate_auditd_packages_installed,
        evidence=_evidence_auditd_packages_installed,
    ),
    Check(
        id="aide_installed",
        evaluate=_evaluate_aide_installed,
        evidence=_evidence_aide_installed,
    ),
    # Group Q: passwd/group consistency (round 2)
    Check(
        id="no_duplicate_uids",
        evaluate=_evaluate_no_duplicate_uids,
        evidence=_evidence_no_duplicate_uids,
    ),
    Check(
        id="no_duplicate_gids",
        evaluate=_evaluate_no_duplicate_gids,
        evidence=_evidence_no_duplicate_gids,
    ),
    Check(
        id="no_duplicate_group_names",
        evaluate=_evaluate_no_duplicate_group_names,
        evidence=_evidence_no_duplicate_group_names,
    ),
    Check(
        id="passwd_groups_exist_in_group",
        evaluate=_evaluate_passwd_groups_exist_in_group,
        evidence=_evidence_passwd_groups_exist_in_group,
    ),
    Check(
        id="shadow_group_empty",
        evaluate=_evaluate_shadow_group_empty,
        evidence=_evidence_shadow_group_empty,
    ),
    # Group P: shadow/login.defs/sudoers/pwquality (round 2). None dropped.
    Check(
        id="inactive_password_lock",
        evaluate=_evaluate_inactive_password_lock,
        evidence=_evidence_inactive_password_lock,
    ),
    Check(
        id="last_password_change_in_past",
        evaluate=_evaluate_last_password_change_in_past,
        evidence=_evidence_last_password_change_in_past,
    ),
    Check(
        id="password_expiration_configured",
        evaluate=_evaluate_password_expiration_configured,
        evidence=_evidence_password_expiration_configured,
    ),
    Check(
        id="password_expiration_warning_configured",
        evaluate=_evaluate_password_expiration_warning_configured,
        evidence=_evidence_password_expiration_warning_configured,
    ),
    Check(
        id="system_accounts_no_valid_shell",
        evaluate=_evaluate_system_accounts_no_valid_shell,
        evidence=_evidence_system_accounts_no_valid_shell,
    ),
    Check(
        id="accounts_without_shell_locked",
        evaluate=_evaluate_accounts_without_shell_locked,
        evidence=_evidence_accounts_without_shell_locked,
    ),
    Check(
        id="sudo_use_pty",
        evaluate=_evaluate_sudo_use_pty,
        evidence=_evidence_sudo_use_pty,
    ),
    Check(
        id="pwquality_dictcheck",
        evaluate=_evaluate_pwquality_dictcheck,
        evidence=_evidence_pwquality_dictcheck,
    ),
    # Group R: kernel module availability (cramfs, dccp, freevxfs, hfs, hfsplus,
    # jffs2, rds, sctp, squashfs, tipc, udf, usb-storage). See the group's helper
    # functions above CHECKS for the shared evaluate/evidence logic.
    #
    # A kernel-module-loading audit-rule check was looked at and not
    # implemented: one supported document requires a materially weaker condition
    # than the others (kmod rule only vs kmod rule plus syscall rules), so one
    # evaluate() can't represent both without being wrong for someone.
    *(_kernel_module_check(name, module_type) for name, module_type in _KERNEL_MODULES),
    # Group S: see the comment block above these two definitions
    # (_pam_su_restricted_group / _root_umask_weak_lines). A shell-timeout (TMOUT)
    # candidate was looked at and not implemented: it spans an unbounded glob
    # (/etc/profile.d/*.sh) and needs per-file co-location of value, readonly and
    # export, which requires facts.py to track which file each line came from;
    # approximating it would risk a false PASS/FAIL, so it is left out.
    Check(
        id="su_restricted",
        evaluate=_evaluate_su_restricted,
        evidence=_evidence_su_restricted,
    ),
    Check(
        id="root_umask",
        evaluate=_evaluate_root_umask,
        evidence=_evidence_root_umask,
    ),
    # Group T: full-filesystem scans + root's PATH -- see the comment above
    # this group's evaluate()/evidence() functions.
    Check(
        id="world_writable_secured",
        evaluate=_evaluate_world_writable_secured,
        evidence=_evidence_world_writable_secured,
    ),
    Check(
        id="no_unowned_files",
        evaluate=_evaluate_no_unowned_files,
        evidence=_evidence_no_unowned_files,
    ),
    Check(
        id="root_path_integrity",
        evaluate=_evaluate_root_path_integrity,
        evidence=_evidence_root_path_integrity,
    ),
    # Group: audit rule collection (round 4) -- see the comment block above this
    # group's evaluate()/evidence() functions for the shared old-vs-new rule-syntax
    # rationale. A privileged-commands check was investigated and not implemented
    # (it needs a per-target SUID/SGID enumeration).
    Check(
        id="user_emulation_logged",
        evaluate=_evaluate_user_emulation_logged,
        evidence=_evidence_user_emulation_logged,
    ),
    Check(
        id="time_change_logged",
        evaluate=_evaluate_time_change_logged,
        evidence=_evidence_time_change_logged,
    ),
    Check(
        id="sudo_log_file_logged",
        evaluate=_evaluate_sudo_log_file_logged,
        evidence=_evidence_sudo_log_file_logged,
    ),
    Check(
        id="mac_policy_logged",
        evaluate=_evaluate_mac_policy_logged,
        evidence=_evidence_mac_policy_logged,
    ),
    Check(
        id="logins_logged",
        evaluate=_evaluate_logins_logged,
        evidence=_evidence_logins_logged,
    ),
    Check(
        id="session_logged",
        evaluate=_evaluate_session_logged,
        evidence=_evidence_session_logged,
    ),
    Check(
        id="mounts_logged",
        evaluate=_evaluate_mounts_logged,
        evidence=_evidence_mounts_logged,
    ),
    Check(
        id="unsuccessful_file_access_logged",
        evaluate=_evaluate_unsuccessful_file_access_logged,
        evidence=_evidence_unsuccessful_file_access_logged,
    ),
    # Group V: see the comment block above these checks' evaluate()/evidence()
    # functions. A log-file-permissions candidate was not implemented.
    Check(
        id="single_time_sync_daemon",
        evaluate=_evaluate_single_time_sync_daemon,
        evidence=_evidence_single_time_sync_daemon,
    ),
    Check(
        id="audit_processes_prior_to_auditd",
        evaluate=_evaluate_audit_processes_prior_to_auditd,
        evidence=_evidence_audit_processes_prior_to_auditd,
    ),
    Check(
        id="pwquality_enforcing",
        evaluate=_evaluate_pwquality_enforcing,
        evidence=_evidence_pwquality_enforcing,
    ),
    # Local interactive user home directory / dot files checks (round 4).
    # "Local interactive user" is defined via /etc/shells shell membership, not a
    # UID_MIN cutoff -- see _local_interactive_users()'s docstring.
    Check(
        id="interactive_user_home_dirs",
        evaluate=_evaluate_interactive_user_home_dirs,
        evidence=_evidence_interactive_user_home_dirs,
    ),
    Check(
        id="interactive_user_dotfiles",
        evaluate=_evaluate_interactive_user_dotfiles,
        evidence=_evidence_interactive_user_dotfiles,
    ),
    # Group U: the auditd.conf family (checks-backlog.md's "Group A", see the
    # comment above facts.audit_conf_text and this group's own helper functions
    # for the audit-tools scope difference).
    Check(
        id="audit_conf_files_mode",
        evaluate=_evaluate_audit_conf_files_mode,
        evidence=_evidence_audit_conf_files_mode,
    ),
    Check(
        id="audit_log_files_group_owner",
        evaluate=_evaluate_audit_log_files_group_owner,
        evidence=_evidence_audit_log_files_group_owner,
    ),
    Check(
        id="audit_log_files_mode",
        evaluate=_evaluate_audit_log_files_mode,
        evidence=_evidence_audit_log_files_mode,
    ),
    Check(
        id="audit_log_files_owner",
        evaluate=_evaluate_audit_log_files_owner,
        evidence=_evidence_audit_log_files_owner,
    ),
    Check(
        id="audit_log_storage_size",
        evaluate=_evaluate_audit_log_storage_size,
        evidence=_evidence_audit_log_storage_size,
    ),
    Check(
        id="audit_logs_not_auto_deleted",
        evaluate=_evaluate_audit_logs_not_auto_deleted,
        evidence=_evidence_audit_logs_not_auto_deleted,
    ),
    Check(
        id="audit_tools_mode",
        evaluate=_evaluate_audit_tools_mode,
        evidence=_evidence_audit_tools_mode,
    ),
    Check(
        id="audit_disk_full_error_actions",
        evaluate=_evaluate_audit_disk_full_error_actions,
        evidence=_evidence_audit_disk_full_error_actions,
    ),
    Check(
        id="audit_space_left_actions",
        evaluate=_evaluate_audit_space_left_actions,
        evidence=_evidence_audit_space_left_actions,
    ),
    Check(
        id="audit_log_dir_mode",
        evaluate=_evaluate_audit_log_dir_mode,
        evidence=_evidence_audit_log_dir_mode,
    ),
    # checks-backlog.md Group B -- see the comment above each evaluate()
    # function for why both are implementable without infra changes.
    Check(
        id="timesyncd_authorized_timeserver",
        evaluate=_evaluate_timesyncd_authorized_timeserver,
        evidence=_evidence_timesyncd_authorized_timeserver,
    ),
    Check(
        id="journal_remote_not_in_use",
        evaluate=_evaluate_journal_remote_not_in_use,
        evidence=_evidence_journal_remote_not_in_use,
    ),
    # checks-backlog.md Group C's partition family -- see the module comment
    # above _MOUNT_OPTION_CANDIDATES/_SEPARATE_PARTITION_CANDIDATES for how the 2
    # bonus /tmp+/dev/shm candidates were found.
    *[
        _mount_option_check(check_id, target, option)
        for check_id, target, option in _MOUNT_OPTION_CANDIDATES
    ],
    *[
        _separate_partition_check(check_id, target)
        for check_id, target in _SEPARATE_PARTITION_CANDIDATES
    ],
    # checks-backlog.md "Grupo C -- systemd real" -- see the module comment
    # above _parse_systemd_service_status for the conditional/unconditional split
    # across these 6.
    Check(
        id="auditd_enabled_active",
        evaluate=_evaluate_auditd_enabled_active,
        evidence=_evidence_auditd_enabled_active,
    ),
    Check(
        id="chrony_enabled_active",
        evaluate=_evaluate_chrony_enabled_active,
        evidence=_evidence_chrony_enabled_active,
    ),
    Check(
        id="chrony_runs_as_chrony_user",
        evaluate=_evaluate_chrony_runs_as_chrony_user,
        evidence=_evidence_chrony_runs_as_chrony_user,
    ),
    Check(
        id="cron_enabled_active",
        evaluate=_evaluate_cron_enabled_active,
        evidence=_evidence_cron_enabled_active,
    ),
    Check(
        id="timesyncd_enabled_active",
        evaluate=_evaluate_timesyncd_enabled_active,
        evidence=_evidence_timesyncd_enabled_active,
    ),
    Check(
        id="audit_rules_running_matches_disk",
        evaluate=_evaluate_audit_rules_running_matches_disk,
        evidence=_evidence_audit_rules_running_matches_disk,
    ),
]


def document_slug_for_os(os_id: str, version_id: str) -> str:
    """Maps a detected OS id/version to the matching document slug used by
    invariant_ingestion, e.g. ("debian", "11") -> "debian_linux_11",
    ("ubuntu", "20.04") -> "ubuntu_linux_20_04". Pure string logic, no
    Postgres/network needed -- safe to keep here even though the slug it
    returns is only meaningful to whoever (invariant_api) actually looks
    controls up by it.
    """
    return f"{os_id}_linux_{version_id.replace('.', '_')}"


def family_for_os(os_id: str, os_version_id: str) -> str:
    """Maps a detected OS id to the Check.family group that applies to
    it. Both "debian" and "ubuntu" share one family today (same
    systemd, same /etc/shadow, same shell tooling) -- os_version_id is
    accepted (not used yet) so this has the same signature shape as
    document_slug_for_os() and room to matter once a family needs
    version-level splits.
    """
    if os_id in ("debian", "ubuntu"):
        return "debian_ubuntu"
    raise LookupError(f"no check family known for os_id={os_id!r}")
