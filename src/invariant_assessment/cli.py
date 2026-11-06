"""`invariant assess` -- the same engine as the HTTP service, from a terminal.

Exit codes: 0 = the assessment ran (FAIL results included); 2 = usage error;
3 = could not reach / read the target. 1 is reserved for the future
`invariant gate`: this command never returns it.
"""

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
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


def load_catalog() -> tuple[dict, str]:
    raw = CATALOG_PATH.read_bytes()
    return json.loads(raw)["checks"], hashlib.sha256(raw).hexdigest()


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
    if probe_ok and "PROC ok" in lines:
        proc = "present" if any(ln.startswith(f"PROCNAME {name}") for ln in lines) else "absent"
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


def assess(args) -> dict:
    from fastapi import HTTPException

    from invariant_assessment.api import _evaluate_all
    from invariant_assessment.facts import collect_facts

    _validate(args)
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
        raise TransportError(str(e.detail)) from e
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
    try:
        out = assess(args)
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
    except LookupError:
        print("invariant: could not collect facts from the target (no shell, not running or not found)", file=sys.stderr)
        return 3
    except Exception as e:  # never leak 1 (reserved for the gate) nor a traceback with locals
        print(f"invariant: unexpected error ({type(e).__name__})", file=sys.stderr)
        return 3
    print(json.dumps(out, indent=2) if args.format == "json" else render_table(out))
    return 0


if __name__ == "__main__":
    sys.exit(main())
