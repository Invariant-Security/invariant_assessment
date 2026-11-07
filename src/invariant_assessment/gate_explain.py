"""INV-85: own-words explanation (where / why / exploit / fix) for each gate block reason.

Texts are written for this project; they carry no third-party benchmark wording. No process
data (pid, executable path, library, port) ever goes in here: only the target, the check
evidence (already public in `assess`) and package/CVE fields.
"""

ASSUMPTIONS = [
    "The gate evaluates the container running in CI; the production context may differ.",
    "With the --docker target, the Invariant image needs the Docker socket, which is equivalent to root on the pipeline "
    "host (to be resolved by INV-04).",
]

_PERM = "Other users could change it and take over accounts or escalate privileges."
_PERM_FIX = "Restore the owner and the restrictive mode this file should have, and fix the image build step that loosened it."

# check_id -> (why, exploit, fix)
CHECK_TEXT = {
    "etc_group_permissions": (
        "The group database must be owned by root and not writable by others; here it is not.",
        "An unprivileged user edits it to add themselves to a privileged group, gaining that group's access.", _PERM_FIX),
    "etc_gshadow_permissions": (
        "The group password database must be owned by root and unreadable by ordinary users; here it is not.",
        "A local user reads or alters group password hashes and uses them to join or crack privileged groups.", _PERM_FIX),
    "etc_passwd_permissions": (
        "The account database must be owned by root and not writable by others; here it is not.",
        "An unprivileged user adds an account with UID 0 or changes an existing entry, obtaining root.", _PERM_FIX),
    "etc_shadow_permissions": (
        "The password hash file must be owned by root and unreadable by ordinary users; here it is not.",
        "A local user (or a compromised service account) reads the hashes and cracks them offline, or rewrites them to set a known password.",
        _PERM_FIX),
    "passwd_accounts_use_shadowed_passwords": (
        "Some accounts keep their password hash in the world-readable account file instead of the protected hash file.",
        "Any local user copies the hash and cracks it offline, then logs in as that account.",
        "Move every hash to the protected hash file (convert the accounts) and lock accounts that do not need a password."),
    "root_only_uid0_account": (
        "More than one account has UID 0, so more than one identity is root.",
        "Anyone who obtains the extra account's credentials has full root access, often under a name nobody monitors.",
        "Remove the extra UID 0 accounts, or give them a normal UID if they are legitimate."),
    "root_path_integrity": (
        "The command search path of root contains a relative or writable directory.",
        "An attacker drops a binary named like a common command in that directory; when root runs it, the attacker's code runs as root.",
        "Remove empty, relative and writable directories from root's search path and make the remaining ones root-owned."),
    "shadow_password_fields_not_empty": (
        "At least one account has an empty password field.",
        "Anyone who can reach a login prompt (console, su, SSH if allowed) signs in as that account without a password.",
        "Set a strong password or lock the account (or remove it if unused)."),
    "ssh_permit_empty_passwords": (
        "The SSH server accepts logins from accounts with an empty password.",
        "A remote attacker connects over the network and authenticates as any passwordless account.",
        "Disable empty passwords in the SSH server configuration and reload the service; prefer key authentication."),
    "ssh_permit_root_login": (
        "The SSH server allows direct login as root.",
        "Remote attackers can brute-force or replay stolen root credentials directly over the network, with no privilege escalation step.",
        "Disable direct root login in the SSH server configuration, reload the service and use a named account plus controlled elevation."),
    "ssh_private_host_key_permissions": (
        "The SSH server private host keys are readable or writable by users other than root.",
        "A local user copies the key and impersonates the server (man-in-the-middle), or replaces it.",
        "Make the private host keys root-owned and not accessible to others; regenerate them if they may have been read."),
    "sudo_no_nopasswd": (
        "The sudo configuration lets some principals run commands as root without a password.",
        "Any process or user running as such a principal (for example after an application compromise) becomes root with no further barrier.",
        "Remove the passwordless rules, or restrict them to specific commands that cannot spawn a shell."),
    "tftp_server_not_installed": (
        "A TFTP server is installed; it serves files with no authentication.",
        "A network attacker reads or uploads files (configs, keys, payloads) through the unauthenticated service.",
        "Remove the package, or replace it by an authenticated transfer method."),
    "world_writable_secured": (
        "World-writable directories lack the protection that stops users from deleting or replacing each other's files.",
        "A local user swaps or removes files another user or service depends on (symlink and race attacks), leading to privilege escalation.",
        "Set the sticky bit on shared writable directories, or remove world write access."),
    "xinetd_not_installed": (
        "The legacy internet super-server is installed; it can expose old network services.",
        "It widens the network attack surface with services that are rarely patched or monitored.",
        "Remove the package, and run any needed service on its own with explicit configuration."),
}

_NOT_ASSESSED_FIX = ("Re-run with enough privilege inside the target and a working transport (container exec or SSH) so the check "
                     "can be evaluated, or add a justified, time-limited exception.")


def _evidence(r):
    ev = " ".join(str((r or {}).get("evidence") or "").split())
    return ev[:200] if ev else "no evidence collected"


def explain_check(cid: str, state: str, result: dict | None, target: str) -> dict:
    if state == "NOT_ASSESSED":
        missing = result is None
        return {
            "where": f"{target}: critical check {cid} " + ("was not in the results" if missing else f"could not be evaluated ({_evidence(result)})"),
            "why": "The check could not be assessed, so it is unknown whether the target is safe; the gate fails closed and blocks.",
            "exploit": "Not assessed: if the control is broken, the weakness listed for this check stays undetected.",
            "fix": _NOT_ASSESSED_FIX,
        }
    why, exploit, fix = CHECK_TEXT.get(cid) or (
        "A critical check failed.", "The weakness measured by this check can be abused by an attacker.", "Correct the setting the check reports.")
    return {"where": f"{target}: {_evidence(result)}", "why": why, "exploit": exploit, "fix": fix}


def explain_cve(cve: str, fs: list[dict], target: str) -> dict:
    f0 = fs[0]
    pk = sorted({f"{f['package']} {f.get('installed_version') or '?'}" for f in fs})
    unknown = not any(f["exposure"] == "exposed" for f in fs)
    kev = f"listed in CISA KEV (added {f0.get('kev_date_added') or 'n/a'}; ransomware use: {f0.get('kev_known_ransomware_campaign_use') or 'n/a'})"
    sev = f"severity {f0.get('severity') or 'n/a'}, CVSS v3 {f0.get('cvss_v3_score') if f0.get('cvss_v3_score') is not None else 'n/a'}"
    epss = f"EPSS {f0['epss_score']}" if f0.get("epss_score") is not None else "EPSS n/a"
    expo = ("exposed: a process listening on a non-loopback address loads a library of the package" if not unknown
            else "unknown: it could not be proven that the package is not exposed")
    fixed = sorted({f["fixed_version"] for f in fs if f.get("fixed_version")})
    fix = (f"Update {', '.join(sorted({f['package'] for f in fs}))} to {', '.join(fixed)} and rebuild the image. "
           if fixed else "No fixed version is published: remove the package or turn off the listening service. ")
    return {
        "where": f"{target}: package(s) {', '.join(pk)}",
        "why": f"{cve} is {kev}; {sev}; {epss}; {expo}.",
        "exploit": ("Actively exploited in the wild according to the KEV; reachable over the network because a listening process "
                    "loads the vulnerable code" + ("." if not unknown else " (cannot be ruled out here).")),
        "fix": fix + "Otherwise record an exception with justification, owner and expiry.",
    }


# --- INV-105: plain-language title/action (reasons[].title / .action) and phrases for context codes ---

# check_id -> (title, action). Written for this project, no benchmark wording.
CHECK_PLAIN = {
    "etc_group_permissions": ("The group list file can be changed by other users",
                              "Make the file owned by root and not writable by others, and fix the build step that changed it."),
    "etc_gshadow_permissions": ("The group password file is open to ordinary users",
                                "Make the file owned by root and unreadable by ordinary users, and fix the build step that opened it."),
    "etc_passwd_permissions": ("The user account list can be changed by other users",
                               "Make the file owned by root and not writable by others, and fix the build step that changed it."),
    "etc_shadow_permissions": ("Password hashes can be read by ordinary users",
                               "Make the file owned by root and unreadable by ordinary users, and fix the build step that opened it."),
    "passwd_accounts_use_shadowed_passwords": ("Some accounts keep their password hash in a file everyone can read",
                                               "Move those hashes to the protected password file, or lock the accounts."),
    "root_only_uid0_account": ("More than one account has full administrator powers",
                               "Remove the extra accounts, or give them a normal user number."),
    "root_path_integrity": ("The administrator's command search path includes an unsafe folder",
                            "Remove empty, relative and writable folders from that path."),
    "shadow_password_fields_not_empty": ("An account has no password",
                                         "Set a strong password on the account, lock it, or remove it."),
    "ssh_permit_empty_passwords": ("The SSH server accepts logins without a password",
                                   "Turn off empty passwords in the SSH server settings and reload it."),
    "ssh_permit_root_login": ("The SSH server lets people log in directly as administrator",
                              "Turn off direct administrator login in the SSH server settings, reload it and use a named account instead."),
    "ssh_private_host_key_permissions": ("The SSH server's private keys are open to other users",
                                         "Make the keys readable only by root, and regenerate them if someone may have read them."),
    "sudo_no_nopasswd": ("Some accounts can run administrator commands without a password",
                         "Remove those rules, or limit them to specific commands that cannot open a shell."),
    "tftp_server_not_installed": ("A file-transfer server with no login is installed",
                                  "Remove the package."),
    "world_writable_secured": ("Shared writable folders let users delete each other's files",
                               "Turn on the sticky bit on those folders, or remove write access for everyone."),
    "xinetd_not_installed": ("An old network service launcher is installed",
                             "Remove the package and run any needed service on its own."),
}

_NA_ACTION = ("Run the gate with enough privilege inside the target, and with a working connection to it, so the check can run; "
              "or record an exception with an owner and an expiry date.")
_NO_FIX = ("No fixed version exists: remove the package or turn off the service that uses it; "
           "or record an exception with an owner and an expiry date.")

# context_reason -> sentence for humans (JSON and JUnit keep the code)
CONTEXT_PHRASE = {
    "listener_maps_package": "a process listening on the network loads this library",
    "not_executable": "headers or docs only, nothing runs",
    "interpreted_code": "contains scripts, exposure can't be ruled out",
    "not_in_dpkg": "not managed by the OS package manager, could not be checked",
    "no_dpkg": "the OS package list could not be read, could not be checked",
    "not_loaded_by_listener": "installed, but no network-facing process loads it",
    "unreadable": "process data could not be read",
}


def phrase(code) -> str:
    return CONTEXT_PHRASE.get(code, "not classified")


def plain_check(cid: str, state: str) -> tuple[str, str]:
    title, action = CHECK_PLAIN.get(cid, (f"Critical check {cid} failed", "Correct the setting the check reports."))
    if state == "NOT_ASSESSED":
        return f"Could not verify: {title[0].lower()}{title[1:]}", _NA_ACTION
    return title, action


def plain_cve(cve: str, fs: list[dict], state: str) -> tuple[str, str]:
    pk = ", ".join(sorted({f["package"] for f in fs}))
    what = "reachable from the network" if state == "exposed" else "exposure can't be ruled out"
    fixed = sorted({f["fixed_version"] for f in fs if f.get("fixed_version")})
    action = f"Update {pk} to {', '.join(fixed)} and rebuild the image." if fixed else _NO_FIX
    return f"{cve} in {pk}: actively exploited, {what}", action
