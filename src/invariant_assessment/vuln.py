"""CVEs of an image via the embedded Trivy (INV-81). Development entry point only:
`python -m invariant_assessment.vuln <image> | --docker <container>`; no `invariant`
subcommand. It scans the IMAGE (ID resolved from the container), never the running
container, fully offline from a vulnerability DB kept in INVARIANT_TRIVY_CACHE.

Exit codes: 0 ok; 2 usage; 4 any failure (Trivy missing/failing, invalid JSON, DB or
Java DB missing, DB too old). Never 1 (reserved for the gate) and never 0 on failure.
"""

import argparse
import json
import os
import re
import subprocess
import sys
import traceback
from datetime import datetime, timezone

CACHE_ENV = "INVARIANT_TRIVY_CACHE"
WARN_ENV, MAX_ENV = "INVARIANT_TRIVY_DB_WARN_DAYS", "INVARIANT_TRIVY_DB_MAX_DAYS"


class VulnError(Exception):
    """Exit 4. Fixed short message, no scan data."""


def _run(argv: list[str], timeout: int) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
    except FileNotFoundError as e:
        raise VulnError(f"{argv[0]} not found in PATH") from e
    except subprocess.TimeoutExpired as e:
        raise VulnError(f"{argv[0]} timed out") from e


def _parse_ts(value: str) -> datetime:
    # Trivy prints nanoseconds; fromisoformat takes at most 6 fractional digits.
    value = re.sub(r"(\.\d{6})\d+", r"\1", value.replace("Z", "+00:00"))
    return datetime.fromisoformat(value)


def _days_env(name: str, default: int) -> float:
    try:
        return float(os.environ.get(name, default))
    except ValueError as e:
        raise VulnError(f"{name} is not a number") from e


def db_info(cache_dir: str, now: datetime) -> dict:
    """Trivy version + DB freshness from `trivy version --format json`. Raises VulnError
    if a DB is missing or the vulnerability DB is at/over the max age."""
    r = _run(["trivy", "version", "--format", "json", "--cache-dir", cache_dir], 30)
    if r.returncode != 0:
        raise VulnError(f"trivy version exited with code {r.returncode}")
    try:
        v = json.loads(r.stdout)
        trivy_version = v["Version"]
    except (ValueError, KeyError, TypeError) as e:
        raise VulnError("trivy version returned invalid JSON") from e
    if not isinstance(v.get("VulnerabilityDB"), dict) or not isinstance(v.get("JavaDB"), dict):
        raise VulnError("vulnerability DB or Java DB missing in the cache (see README, offline setup)")
    try:
        updated = _parse_ts(v["VulnerabilityDB"]["UpdatedAt"])
        java_updated = _parse_ts(v["JavaDB"]["UpdatedAt"])
        db_version = v["VulnerabilityDB"]["Version"]
    except (KeyError, ValueError, TypeError) as e:
        raise VulnError("trivy version returned an unexpected DB description") from e
    warn_days, max_days = _days_env(WARN_ENV, 3), _days_env(MAX_ENV, 7)
    age = (now - updated).total_seconds() / 86400
    java_age = (now - java_updated).total_seconds() / 86400
    if max(age, java_age) >= max_days:
        raise VulnError(f"vulnerability DB is {max(age, java_age):.1f} days old (limit {max_days:g}); update it")
    warning = f"vulnerability DB is {age:.1f} days old (warning after {warn_days:g})" if age > warn_days else None
    return {"trivy_version": trivy_version, "db_version": db_version, "db_updated_at": updated.isoformat(),
            "db_age_days": round(age, 2), "db_age_warning": warning}


def _cvss_v3(cvss: dict | None) -> float | None:
    """NVD first, otherwise the first vendor that has a v3 score. Informational only."""
    cvss = cvss or {}
    for source in ["nvd", *[k for k in cvss if k != "nvd"]]:
        score = (cvss.get(source) or {}).get("V3Score")
        if score is not None:
            return score
    return None


def normalize(report: dict) -> list[dict]:
    """Findings from a Trivy JSON report, deduplicated by (cve, package)."""
    seen: dict[tuple, dict] = {}
    for result in report.get("Results") or []:
        for v in result.get("Vulnerabilities") or []:
            key = (v["VulnerabilityID"], v["PkgName"])
            seen.setdefault(key, {
                "cve": v["VulnerabilityID"],
                "package": v["PkgName"],
                "installed_version": v.get("InstalledVersion"),
                "fixed_version": v.get("FixedVersion") or None,
                "severity": v.get("Severity"),
                "cvss_v3_score": _cvss_v3(v.get("CVSS")),
            })
    return list(seen.values())


def resolve_image(image: str | None, container: str | None) -> dict:
    """What to scan and what to report: the local image ID is scanned; the report
    names the registry digest when there is one, else the ID."""
    def docker(*a):
        r = _run(["docker", *a], 30)
        return r.stdout.strip() if r.returncode == 0 else ""

    image_id = docker("inspect", "-f", "{{.Image}}", container) if container else docker("image", "inspect", "-f", "{{.Id}}", image)
    if container and not image_id:
        raise VulnError("container not found")
    if not image_id:  # not a local image: let Trivy resolve the name itself
        return {"scan": image, "ref": image, "kind": "name"}
    try:
        digests = json.loads(docker("image", "inspect", "-f", "{{json .RepoDigests}}", image_id) or "null") or []
    except ValueError:
        digests = []
    if digests:
        return {"scan": image_id, "ref": digests[0].split("@", 1)[-1], "kind": "repo_digest"}
    return {"scan": image_id, "ref": image_id, "kind": "image_id"}


def scan(image: str | None, container: str | None, cache_dir: str, now: datetime | None = None) -> dict:
    info = db_info(cache_dir, now or datetime.now(timezone.utc))
    target = resolve_image(image, container)
    r = _run(["trivy", "image", "--scanners", "vuln", "-f", "json", "-q", "--cache-dir", cache_dir,
              "--cache-backend", "memory", "--skip-db-update", "--skip-java-db-update", "--offline-scan",
              "--skip-check-update", target["scan"]], 900)
    if r.returncode != 0:
        raise VulnError(f"trivy exited with code {r.returncode}")
    try:
        report = json.loads(r.stdout)
        findings = normalize(report)
    except (ValueError, KeyError, TypeError, AttributeError) as e:
        raise VulnError("trivy returned invalid JSON") from e
    return {
        "image_ref": {"ref": target["ref"], "kind": target["kind"]},
        "trivy_version": info["trivy_version"],
        "db_version": info["db_version"],
        "db_updated_at": info["db_updated_at"],
        "db_age_days": info["db_age_days"],
        "db_age_warning": info["db_age_warning"],
        "total_findings": len(findings),
        "unique_cves": len({f["cve"] for f in findings}),
        "findings": findings,
    }


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="python -m invariant_assessment.vuln")
    t = p.add_mutually_exclusive_group(required=True)
    t.add_argument("image", nargs="?")
    t.add_argument("--docker", metavar="CONTAINER")
    p.add_argument("--cache-dir", default=os.environ.get(CACHE_ENV))
    try:
        args = p.parse_args(argv)
    except SystemExit as e:
        return int(e.code or 0)
    if not args.cache_dir:
        print(f"vuln: usage error: set {CACHE_ENV} or pass --cache-dir", file=sys.stderr)
        return 2
    try:
        out = scan(args.image, args.docker, args.cache_dir)
    except Exception as e:
        msg = str(e) if isinstance(e, VulnError) else f"unexpected error ({type(e).__name__})"
        print(f"vuln: error: {msg}", file=sys.stderr)
        if os.environ.get("INVARIANT_DEBUG") == "1":
            traceback.print_exc()
        return 4
    if out["db_age_warning"]:
        print(f"vuln: warning: {out['db_age_warning']}", file=sys.stderr)
    print(json.dumps(out, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
