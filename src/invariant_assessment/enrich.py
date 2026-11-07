"""KEV + EPSS enrichment of the Trivy findings (INV-82). Development entry point only:
`python -m invariant_assessment.enrich <image> | --docker <container>`. Runs the
`vuln` scan and adds, per finding, CISA KEV and FIRST EPSS data read from the offline
feeds that `python -m invariant_assessment.prepare` stored in INVARIANT_TRIVY_CACHE/feeds.
No network, no writes: the cache can be mounted read-only.

Exit codes: 0 ok; 2 usage; 4 any failure (scan, feed missing/corrupt/sha256 mismatch/too
old). Never 1 (reserved for the gate, INV-84).
"""

import argparse
import csv
import hashlib
import io
import json
import os
import sys
import traceback
from datetime import datetime, timezone
from pathlib import Path

from invariant_assessment import vuln
from invariant_assessment.vuln import CACHE_ENV, MAX_ENV, WARN_ENV, VulnError

FEEDS_DIR, MANIFEST = "feeds", "manifest.json"
KEV_FILE, EPSS_FILE = "kev.json", "epss.csv"
SEVERITY_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def parse_kev(data: bytes) -> tuple[dict, str]:
    """({cve: entry}, catalogVersion). Raises VulnError if the shape is wrong."""
    try:
        d = json.loads(data)
        version = d["catalogVersion"]
        entries = {v["cveID"]: v for v in d["vulnerabilities"]}
    except (ValueError, KeyError, TypeError) as e:
        raise VulnError("KEV feed is invalid") from e
    if not isinstance(version, str) or not entries:
        raise VulnError("KEV feed is invalid")
    return entries, version


def parse_epss(data: bytes) -> tuple[dict, str]:
    """({cve: (score, percentile)}, score_date as YYYY-MM-DD). Header must be cve,epss,percentile."""
    lines = data.decode("utf-8", "replace").splitlines()
    date = None
    if lines and lines[0].startswith("#"):
        for part in lines.pop(0).lstrip("#").split(","):
            if part.startswith("score_date:"):
                date = part.split(":", 1)[1][:10]
    if not date or not lines or [c.strip() for c in lines[0].split(",")] != ["cve", "epss", "percentile"]:
        raise VulnError("EPSS feed is invalid")
    try:
        scores = {r[0]: (float(r[1]), float(r[2])) for r in csv.reader(io.StringIO("\n".join(lines[1:]))) if r}
    except (ValueError, IndexError) as e:
        raise VulnError("EPSS feed is invalid") from e
    if not scores:
        raise VulnError("EPSS feed is invalid")
    return scores, date


def load_feeds(cache_dir: str, now: datetime) -> dict:
    """Read, verify (sha256 vs manifest, content, age by fetched_at) and parse both feeds."""
    base = Path(cache_dir) / FEEDS_DIR
    try:
        manifest = json.loads((base / MANIFEST).read_text())
        meta = {k: manifest[k] for k in ("kev", "epss")}
        raw = {}
        for k, name in (("kev", KEV_FILE), ("epss", EPSS_FILE)):
            raw[k] = (base / name).read_bytes()
            if hashlib.sha256(raw[k]).hexdigest() != meta[k]["sha256"]:
                raise VulnError(f"{k.upper()} feed does not match the manifest sha256")
            meta[k]["_fetched"] = datetime.fromisoformat(meta[k]["fetched_at"])
    except VulnError:
        raise
    except (OSError, ValueError, KeyError, TypeError, AttributeError) as e:
        raise VulnError("KEV/EPSS feeds missing or manifest unreadable (run invariant_assessment.prepare)") from e
    warn_days, max_days = vuln._days_env(WARN_ENV, 3), vuln._days_env(MAX_ENV, 7)
    ages = {k: (now - meta[k]["_fetched"]).total_seconds() / 86400 for k in meta}
    for k, age in ages.items():
        if age >= max_days:
            raise VulnError(f"{k.upper()} feed is {age:.1f} days old (limit {max_days:g}); run prepare")
    kev, kev_version = parse_kev(raw["kev"])
    if meta["kev"].get("catalogVersion") != kev_version:
        raise VulnError("KEV catalogVersion does not match the manifest")
    epss, epss_date = parse_epss(raw["epss"])
    warnings = [f"{k.upper()} feed is {a:.1f} days old (warning after {warn_days:g})" for k, a in ages.items() if a > warn_days]
    return {"kev": kev, "epss": epss, "epss_date": epss_date, "kev_catalog_version": kev_version,
            "feeds": {k: {"fetched_at": meta[k]["fetched_at"], "sha256": meta[k]["sha256"]} for k in meta},
            "warning": "; ".join(warnings) or None}


def enrich(findings: list[dict], feeds: dict) -> list[dict]:
    out = []
    for f in findings:
        k, e = feeds["kev"].get(f["cve"]), feeds["epss"].get(f["cve"])
        out.append({**f,
                    "in_kev": k is not None,
                    "kev_date_added": k.get("dateAdded") if k else None,
                    "kev_known_ransomware_campaign_use": k.get("knownRansomwareCampaignUse") if k else None,
                    "epss_score": e[0] if e else None,
                    "epss_percentile": e[1] if e else None,
                    "epss_date": feeds["epss_date"] if e else None})
    # in_kev desc, epss desc (null last), then severity; sort is stable
    return sorted(out, key=lambda f: (not f["in_kev"], f["epss_score"] is None, -(f["epss_score"] or 0),
                                      SEVERITY_RANK.get(f["severity"], 4)))


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="python -m invariant_assessment.enrich")
    t = p.add_mutually_exclusive_group(required=True)
    t.add_argument("image", nargs="?")
    t.add_argument("--docker", metavar="CONTAINER")
    p.add_argument("--cache-dir", default=os.environ.get(CACHE_ENV))
    try:
        args = p.parse_args(argv)
    except SystemExit as e:
        return int(e.code or 0)
    if not args.cache_dir:
        print(f"enrich: usage error: set {CACHE_ENV} or pass --cache-dir", file=sys.stderr)
        return 2
    try:
        now = datetime.now(timezone.utc)
        feeds = load_feeds(args.cache_dir, now)  # before the (slow) scan: fail fast
        out = vuln.scan(args.image, args.docker, args.cache_dir, now)
        out["findings"] = enrich(out["findings"], feeds)
        out["kev_catalog_version"] = feeds["kev_catalog_version"]
        out["feeds"] = feeds["feeds"]
        out["feeds_age_warning"] = feeds["warning"]
        out["unique_cves_in_kev"] = len({f["cve"] for f in out["findings"] if f["in_kev"]})
    except Exception as e:
        msg = str(e) if isinstance(e, VulnError) else f"unexpected error ({type(e).__name__})"
        print(f"enrich: error: {msg}", file=sys.stderr)
        if os.environ.get("INVARIANT_DEBUG") == "1":
            traceback.print_exc()
        return 4
    for w in (out["db_age_warning"], out["feeds_age_warning"]):
        if w:
            print(f"enrich: warning: {w}", file=sys.stderr)
    print(json.dumps(out, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
