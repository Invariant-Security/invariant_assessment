"""`invariant assess` -- the same engine as the HTTP service, from a terminal.

Exit codes: 0 = the assessment ran (FAIL results included); 2 = usage error;
3 = transport (unreachable, auth, host key, missing container); 4 = internal
error (unsupported/undetected OS, bad catalog, unexpected exception; a short
message, traceback only with INVARIANT_DEBUG=1). 1 is only returned by `invariant gate`
(gate.py): this command never returns it.
"""

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import traceback
from datetime import datetime, timezone
from importlib import metadata
from pathlib import Path

import paramiko

from invariant_assessment.facts import SystemFacts
from invariant_assessment.transport import (
    DockerExecTransport,
    HostKeyMismatch,
    LocalTransport,
    SSHTransport,
    TransportAuthError,
    TransportError,
    TransportTimeoutError,
    TransportUnreachableError,
    host_key_fingerprint,
)

CATALOG_PATH = Path(__file__).with_name("catalog.json")
_FP_RE = re.compile(r"^SHA256:[A-Za-z0-9+/]{43}$")
_KEY_TYPES = ("ssh-ed25519", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521", "ssh-rsa")
_REQUIRES_PKG = {"sshd": "openssh-server", "sudo": "sudo"}


class UsageError(Exception):
    pass


class InternalError(Exception):
    """Exit 4. The message is fixed text -- never data from the target."""


def load_catalog() -> tuple[dict, str]:
    try:
        raw = CATALOG_PATH.read_bytes()
        data = json.loads(raw)
        checks = data["checks"]
        ok = data["schema"] == 1 and isinstance(checks, dict) and all(
            isinstance(m, dict) and set(m) == {"critical", "host_only", "requires"}
            and isinstance(m["critical"], bool) and isinstance(m["host_only"], bool)
            and m["requires"] in (None, "sshd", "sudo") for m in checks.values())
    except (OSError, ValueError, KeyError, TypeError) as e:
        raise InternalError(f"catalog.json missing or corrupt ({type(e).__name__})") from e
    if not ok:
        raise InternalError("catalog.json has an unexpected schema")
    return checks, hashlib.sha256(raw).hexdigest()


# --- effective_status ---------------------------------------------------------


def _requires_signals(facts: SystemFacts, name: str) -> list[str]:
    """present | absent | unknown for the 3 signals: dpkg package, binary on
    PATH, running process. Unknown never counts as absent."""
    pkgs = facts.installed_packages
    if "installed_packages" in facts.unreadable or "installed_packages" in facts.missing or not pkgs:
        pkg = "unknown"
    else:
        pkg = "present" if _REQUIRES_PKG[name] in pkgs else "absent"
    lines = [ln.strip() for ln in facts.applicability_probe_text.splitlines()]
    probe_ok = "applicability_probe_text" not in facts.unreadable
    binary = next((ln.split()[2] for ln in lines if probe_ok and ln.startswith(f"BIN {name} ")), "unknown")
    if probe_ok and "PROC ok" in lines and "PROC unreadable" not in lines:
        proc = "present" if f"RUNNING {name}" in lines else "absent"
    else:
        proc = "unknown"
    return [pkg, binary, proc]


def effective_status(status: str, meta: dict | None, facts: SystemFacts, transport: str) -> str:
    if meta is None:
        return status
    if meta["host_only"] and transport == "docker":
        return "NOT_APPLICABLE"
    if meta["requires"] is None:
        return status
    sig = _requires_signals(facts, meta["requires"])
    if "present" in sig:
        return status
    return "NOT_APPLICABLE" if all(s == "absent" for s in sig) else "NOT_ASSESSED"


# --- targets ------------------------------------------------------------------


def _docker_image(container: str) -> dict:
    def inspect(*args):
        r = subprocess.run(["docker", *args], capture_output=True, text=True, timeout=10)
        return r.stdout.strip() if r.returncode == 0 else ""

    try:
        image_id = inspect("inspect", "-f", "{{.Image}}", container)
        digests = json.loads(inspect("image", "inspect", "-f", "{{json .RepoDigests}}", image_id) or "null") or []
    except (OSError, subprocess.SubprocessError, ValueError):
        return {"image_digest": None, "image_digest_kind": None}
    if digests:
        return {"image_digest": digests[0].split("@", 1)[-1], "image_digest_kind": "repo_digest"}
    if image_id:
        return {"image_digest": image_id, "image_digest_kind": "image_id"}
    return {"image_digest": None, "image_digest_kind": None}


def _parse_ssh(spec: str) -> tuple[str, str, int]:
    m = re.fullmatch(r"([^@\s:]+)@([^@\s:]+)(?::(\d{1,5}))?", spec)
    if not m or int(m[3] or 22) > 65535:
        raise UsageError("--ssh expects user@host[:port]")
    return m[1], m[2], int(m[3] or 22)


def _pins_from_known_hosts(path: str, host: str, port: int) -> list[tuple[str, str]]:
    keys = paramiko.HostKeys()
    try:
        keys.load(path)
    except OSError as e:
        raise UsageError(f"cannot read --known-hosts file: {e.strerror}") from e
    entry = keys.lookup(host if port == 22 else f"[{host}]:{port}")
    pins = [(t, host_key_fingerprint(entry[t])) for t in _KEY_TYPES if entry and t in entry]
    if not pins:
        raise UsageError("no entry for this host in --known-hosts")
    return pins


def _read_key(path: str) -> str:
    try:
        return Path(path).read_text()
    except (OSError, UnicodeDecodeError) as e:
        raise UsageError("cannot read --key file") from e


def _ssh_collect(args, collect):
    user, host, port = _parse_ssh(args.ssh)
    key = _read_key(args.key)
    if args.known_hosts:
        pins = _pins_from_known_hosts(args.known_hosts, host, port)
    else:
        # The fingerprint does not say its key type: try each type, the pin itself
        # is verified against the server's key before any credential is sent.
        pins = [(t, args.host_key_fingerprint) for t in _KEY_TYPES]
    mismatch = None
    for key_type, fp in pins:
        transport = SSHTransport(host=host, port=port, username=user, auth_method="key", key_material=key,
                                 host_key_type=key_type, host_key_fingerprint=fp)
        try:
            return collect(transport), transport
        except HostKeyMismatch as e:
            if mismatch is None or e.fingerprint:
                mismatch = e
    raise mismatch


# --- run ----------------------------------------------------------------------


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="invariant")
    sub = p.add_subparsers(dest="command", required=True)
    a = sub.add_parser("assess", help="run the hardening checks against one target")
    t = a.add_mutually_exclusive_group(required=True)
    t.add_argument("--docker", metavar="CONTAINER")
    t.add_argument("--ssh", metavar="USER@HOST[:PORT]")
    t.add_argument("--local", action="store_true")
    a.add_argument("--key", metavar="PATH", help="private key file (--ssh)")
    a.add_argument("--known-hosts", metavar="PATH")
    a.add_argument("--host-key-fingerprint", metavar="SHA256:...")
    a.add_argument("--format", choices=("json", "table"), default="table")
    g = sub.add_parser("gate", help="assess + CVEs + KEV + container context: exit 0 pass, 1 block")
    t = g.add_mutually_exclusive_group(required=True)
    t.add_argument("--docker", metavar="CONTAINER")
    t.add_argument("--ssh", metavar="USER@HOST[:PORT]")
    t.add_argument("--local", action="store_true")
    g.add_argument("--exceptions", metavar="PATH", help="default: ./.invariant-exceptions.yaml if it exists")
    g.add_argument("--format", choices=("json", "table"), default="table")
    g.set_defaults(key=None, known_hosts=None, host_key_fingerprint=None)
    return p


def _validate(args) -> None:
    if args.ssh:
        if not args.key:
            raise UsageError("--ssh requires --key PATH (key authentication only)")
        if not (args.known_hosts or args.host_key_fingerprint):
            raise UsageError("--ssh requires --known-hosts PATH or --host-key-fingerprint SHA256:... (no trust on first use)")
        if args.host_key_fingerprint and not _FP_RE.match(args.host_key_fingerprint):
            raise UsageError("--host-key-fingerprint must look like SHA256:<43 base64 chars>")
    elif args.key or args.known_hosts or args.host_key_fingerprint:
        raise UsageError("--key, --known-hosts and --host-key-fingerprint only apply to --ssh")


def _warn_if_unprivileged(args) -> None:
    if (args.local and os.geteuid() != 0) or (args.ssh and _parse_ssh(args.ssh)[0] != "root"):
        print("invariant: warning: not running as root. A complete assessment needs root (or CAP_SYS_PTRACE "
              "to read process executables); checks with `requires` (sshd/sudo) may come out NOT_ASSESSED, "
              "and the gate fails closed on that.", file=sys.stderr)


def assess(args) -> dict:
    from fastapi import HTTPException

    from invariant_assessment.api import _evaluate_all
    from invariant_assessment.facts import collect_facts as _collect_facts

    def collect_facts(transport):
        try:
            return _collect_facts(transport)
        except LookupError as e:  # the collection script did not run (no shell, container missing/stopped)
            raise TransportUnreachableError("could not collect facts from the target (no shell, not running or not found)") from e

    _validate(args)
    _warn_if_unprivileged(args)
    catalog, catalog_version = load_catalog()
    started = datetime.now(timezone.utc)
    extra: dict = {}
    host_key: dict = {}
    if args.docker:
        kind, target = "docker", args.docker
        facts = collect_facts(DockerExecTransport(target=target))
        extra = _docker_image(target)
    elif args.local:
        kind, target = "local", "local"
        facts = collect_facts(LocalTransport(timeout=120))  # the full-filesystem finds take long on a real host
    else:
        kind, target = "ssh", args.ssh
        facts, tr = _ssh_collect(args, collect_facts)
        host_key = {"host_key_observed": tr.host_key_observed, "host_key_verification": "operator"}
    try:
        resp = _evaluate_all(facts, target, host_key).model_dump(mode="json")
    except HTTPException as e:
        raise InternalError("target OS not detected or not supported") from e
    for r in resp["results"]:
        r["effective_status"] = effective_status(r["status"], catalog.get(r["check_id"]), facts, kind)
    run_id = next((os.environ[v] for v in ("INVARIANT_RUN_ID", "BUILD_URL", "GITHUB_RUN_ID") if os.environ.get(v)), None)
    return {
        **resp,
        "invariant_version": metadata.version("invariant_assessment"),
        "catalog_version": catalog_version,
        "target": target,
        "transport": kind,
        "started_at": started.isoformat(),
        "finished_at": datetime.now(timezone.utc).isoformat(),
        "run_id": run_id,
        **extra,
    }


def render_table(out: dict) -> str:
    rows = out["results"]
    lines = [f"target: {out['target']} ({out['transport']})  document: {out['document']}  "
             f"invariant {out['invariant_version']}  catalog {out['catalog_version'][:12]}", ""]
    w = max((len(r["check_id"]) for r in rows), default=8)
    lines.append(f"{'CHECK':<{w}}  {'STATUS':<12}  {'EFFECTIVE':<14}  EVIDENCE")
    for r in rows:
        ev = " ".join(r["evidence"].split())[:70]
        lines.append(f"{r['check_id']:<{w}}  {r['status']:<12}  {r['effective_status']:<14}  {ev}")
    counts: dict[str, int] = {}
    for r in rows:
        counts[r["effective_status"]] = counts.get(r["effective_status"], 0) + 1
    lines += ["", "summary: " + ", ".join(f"{k}={v}" for k, v in sorted(counts.items()))]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as e:  # argparse already exits 2 on usage errors
        return int(e.code or 0)
    from invariant_assessment import gate
    from invariant_assessment.vuln import VulnError

    try:
        out = gate.gate(args) if args.command == "gate" else assess(args)
    except UsageError as e:
        print(f"invariant: usage error: {e}", file=sys.stderr)
        return 2
    except HostKeyMismatch as e:
        print(f"invariant: host key mismatch (server presented {e.key_type} {e.fingerprint})", file=sys.stderr)
        return 3
    except TransportAuthError:
        print("invariant: authentication failed", file=sys.stderr)
        return 3
    except (TransportUnreachableError, TransportTimeoutError, TransportError) as e:
        print(f"invariant: transport error: {e}", file=sys.stderr)
        return 3
    except Exception as e:  # `assess` never returns 1; the gate returns it only on a decision
        known = isinstance(e, (InternalError, VulnError))
        print(f"invariant: {'internal error' if known else 'unexpected error'}: {e if known else type(e).__name__}",
              file=sys.stderr)
        if os.environ.get("INVARIANT_DEBUG") == "1":
            traceback.print_exc()
        return 4
    if args.command == "gate":
        for w in out["warnings"]:
            print(f"invariant: warning: {w}", file=sys.stderr)
        print(json.dumps(out, indent=2) if args.format == "json" else gate.render_table(out))
        return 1 if out["decision"] == "block" else 0
    print(json.dumps(out, indent=2) if args.format == "json" else render_table(out))
    return 0


if __name__ == "__main__":
    sys.exit(main())
