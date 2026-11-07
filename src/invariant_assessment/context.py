"""Container context for Trivy findings (INV-83). Development entry point only:
`python -m invariant_assessment.context --docker <container>`; no `invariant` subcommand.
Runs the INV-81 scan (vuln.py) and tags each finding with `exposure` and `context_reason`:

  exposed      ONE process maps a file of the vulnerable package AND owns a socket that
               listens on a non-loopback address (TCP state 0A, UDP bound state 07; wildcard
               v4/v6 count; the v4 loopback range, ::1 and v4-mapped loopback do not).
  not_exposed  the package is installed but no such process exists, or it has nothing
               executable (headers only).
  unknown      anything we could not prove: no dpkg, package not in dpkg (language
               packages), version differs from Trivy's, or a /proc read failed.
               A failed read never turns into not_exposed.

Collected on the target: executable path, mapped file paths, socket inodes, /proc/net/*.
Never cmdline/environ. Process data stays in memory: only the state per finding leaves.

Exit codes: 0 ok; 2 usage; 3 transport; 4 any other failure. Never 1.
"""

import argparse
import ipaddress
import json
import os
import re
import sys
import traceback

from invariant_assessment import vuln
from invariant_assessment.facts import _EXPOSURE_CMD
from invariant_assessment.transport import DockerExecTransport, TransportError

_PKG_RE = re.compile(r"^[a-z0-9][a-z0-9+.\-]*$")
_LISTEN_STATE = {"tcp": "0A", "tcp6": "0A", "udp": "07", "udp6": "07"}
# ponytail: one `dpkg -L` loop per scan; builtins only, forks just for readlink of candidates.
_PKG_CMD = (
    'export LC_ALL=C; exec 2>&1; command -v dpkg >/dev/null 2>&1 || { echo "DPKG absent"; exit 0; }; echo "DPKG ok"; '
    'for p in @PKGS@; do v=$(dpkg-query -W -f=\'${Version}\' "$p" 2>/dev/null) && l=$(dpkg -L "$p" 2>/dev/null) '
    '|| { echo "PKG $p nodpkg"; continue; }; echo "PKG $p ok $v"; '
    'printf "%s\\n" "$l" | while IFS= read -r f; do case "$f" in *.so*) ;; *) [ -f "$f" ] && [ -x "$f" ] || continue;; esac; '
    'echo "F $p $(readlink -f "$f")"; done; done'
)


def _loopback(addr_hex: str) -> bool:
    raw = bytes.fromhex(addr_hex)
    if len(raw) == 4:
        return ipaddress.IPv4Address(raw[::-1]).is_loopback
    ip = ipaddress.IPv6Address(b"".join(raw[i:i + 4][::-1] for i in range(0, 16, 4)))
    return ip.is_loopback or bool(ip.ipv4_mapped and ip.ipv4_mapped.is_loopback)


def parse_probe(text: str) -> dict:
    """{"ok": bool, "procs": [{"files": set, "socks": set}], "listen": set of inodes}.
    ok is False if anything in the collection was unreadable or the block is missing."""
    ok, net_ok, proc_ok, net = True, True, False, None
    procs: list[dict] = []
    listen: set[str] = set()
    for line in text.splitlines():
        line = line.rstrip("\n")
        if line.startswith("NET "):
            net = line[4:].strip()
            net_ok = net_ok and net in _LISTEN_STATE
        elif line == "PROC ok":
            proc_ok = True
        elif line == "PROC unreadable":
            ok = False
        elif line == "P":
            procs.append({"files": set(), "socks": set()})
        elif line.startswith("M ") and procs:
            procs[-1]["files"].add(line[2:].removesuffix(" (deleted)"))
        elif line.startswith("S ") and procs:
            procs[-1]["socks"].add(line[2:].strip())
        elif net in _LISTEN_STATE and re.match(r"\s*\d+:", line):
            f = line.split()
            try:
                if f[3] == _LISTEN_STATE[net] and f[9] != "0" and not _loopback(f[1].split(":")[0]):
                    listen.add(f[9])
            except (IndexError, ValueError):
                ok = False
    return {"ok": ok and net_ok and proc_ok, "procs": procs, "listen": listen}


def parse_packages(text: str) -> dict | None:
    """None if there is no dpkg; else {pkg: {"version": str, "files": set}} for packages dpkg knows."""
    lines = text.splitlines()
    if "DPKG ok" not in lines:
        return None
    pkgs: dict = {}
    for line in lines:
        parts = line.split(" ", 3 if line.startswith("PKG ") else 2)
        if parts[0] == "PKG" and len(parts) == 4 and parts[2] == "ok":
            pkgs[parts[1]] = {"version": parts[3], "files": set()}
        elif parts[0] == "F" and len(parts) == 3 and parts[1] in pkgs:
            pkgs[parts[1]]["files"].add(parts[2])
    return pkgs


def _same_version(trivy: str | None, dpkg: str) -> bool:
    return bool(trivy) and trivy in (dpkg, dpkg.split(":", 1)[-1])


def classify(finding: dict, probe: dict, pkgs: dict | None) -> tuple[str, str]:
    """(exposure, context_reason) of one finding."""
    if pkgs is None:
        return "unknown", "no_dpkg"
    pkg = pkgs.get(finding["package"])
    if pkg is None or not _same_version(finding.get("installed_version"), pkg["version"]):
        return "unknown", "not_in_dpkg"
    if not pkg["files"]:
        return "not_exposed", "not_executable"
    if any(p["files"] & pkg["files"] and p["socks"] & probe["listen"] for p in probe["procs"]):
        return "exposed", "listener_maps_package"
    if not probe["ok"]:
        return "unknown", "unreadable"
    return "not_exposed", "not_loaded_by_listener"


def add_context(report: dict, probe_text: str, pkg_text: str) -> dict:
    probe, pkgs = parse_probe(probe_text), parse_packages(pkg_text)
    for f in report["findings"]:
        f["exposure"], f["context_reason"] = classify(f, probe, pkgs)
    return report


def collect(report: dict, container: str) -> dict:
    """Probe the container and tag the findings of an already-made scan report."""
    tr = DockerExecTransport(target=container, timeout=60)
    names = sorted({f["package"] for f in report["findings"] if _PKG_RE.match(f["package"])})
    probe_text = tr.run("export LC_ALL=C; exec 2>&1; " + _EXPOSURE_CMD)
    pkg_text = tr.run(_PKG_CMD.replace("@PKGS@", " ".join(names))) if names else "DPKG ok"
    return add_context(report, probe_text, pkg_text)


def run(container: str, cache_dir: str) -> dict:
    return collect(vuln.scan(None, container, cache_dir), container)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="python -m invariant_assessment.context")
    p.add_argument("--docker", metavar="CONTAINER", required=True)
    p.add_argument("--cache-dir", default=os.environ.get(vuln.CACHE_ENV))
    try:
        args = p.parse_args(argv)
    except SystemExit as e:
        return int(e.code or 0)
    if not args.cache_dir:
        print(f"context: usage error: set {vuln.CACHE_ENV} or pass --cache-dir", file=sys.stderr)
        return 2
    try:
        out = run(args.docker, args.cache_dir)
    except TransportError:
        print("context: error: could not read the container context (transport)", file=sys.stderr)
        return 3
    except Exception as e:  # fixed messages only: no process data in stderr
        msg = str(e) if isinstance(e, vuln.VulnError) else f"unexpected error ({type(e).__name__})"
        print(f"context: error: {msg}", file=sys.stderr)
        if os.environ.get("INVARIANT_DEBUG") == "1":
            traceback.print_exc()
        return 4
    if out["db_age_warning"]:
        print(f"context: warning: {out['db_age_warning']}", file=sys.stderr)
    print(json.dumps(out, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
