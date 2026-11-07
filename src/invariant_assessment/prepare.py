"""Offline preparation of the scan cache (INV-82). Development entry point only:
`python -m invariant_assessment.prepare [--cache-dir DIR]`. The ONLY step with network
access: Trivy DB + Java DB, CISA KEV and FIRST EPSS go into INVARIANT_TRIVY_CACHE
(feeds/ subfolder + manifest.json). Scans then mount that volume read-only.

Exit 0 ok; 2 usage; 4 any failure (what was in the cache before is kept).
"""

import argparse
import gzip
import hashlib
import json
import os
import sys
import traceback
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

from invariant_assessment import enrich as E
from invariant_assessment.vuln import CACHE_ENV, VulnError, _run

# official CISA mirror (cisagov/kev-data, CC0 1.0), default branch
KEV_URL = "https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json"
EPSS_URL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"  # linked from first.org/epss/data
MAX_BYTES = 200 * 1024 * 1024


def _get(url: str) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "invariant-assessment-prepare"})
    try:
        with urllib.request.urlopen(req, timeout=120) as r:
            data = r.read(MAX_BYTES + 1)
    except Exception as e:  # urllib raises many types; message carries no scan data
        raise VulnError(f"download failed ({type(e).__name__})") from e
    if len(data) > MAX_BYTES:
        raise VulnError("download too large")
    return data


def _write_atomic(path: Path, data: bytes) -> None:
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_bytes(data)
    os.replace(tmp, path)


def prepare_feeds(cache_dir: str, kev_url: str | None = None, epss_url: str | None = None) -> dict:
    kev_raw = _get(kev_url or KEV_URL)
    try:
        epss_raw = gzip.decompress(_get(epss_url or EPSS_URL))
    except (OSError, EOFError) as e:
        raise VulnError("EPSS feed is invalid") from e
    _, kev_version = E.parse_kev(kev_raw)  # validate everything before touching the cache
    _, epss_date = E.parse_epss(epss_raw)
    now = datetime.now(timezone.utc).isoformat()
    sha = lambda b: hashlib.sha256(b).hexdigest()
    manifest = {"kev": {"file": E.KEV_FILE, "fetched_at": now, "sha256": sha(kev_raw), "catalogVersion": kev_version},
                "epss": {"file": E.EPSS_FILE, "fetched_at": now, "sha256": sha(epss_raw), "score_date": epss_date}}
    base = Path(cache_dir) / E.FEEDS_DIR
    base.mkdir(parents=True, exist_ok=True)
    _write_atomic(base / E.KEV_FILE, kev_raw)
    _write_atomic(base / E.EPSS_FILE, epss_raw)
    _write_atomic(base / E.MANIFEST, json.dumps(manifest, indent=2).encode())  # last: a crash before it fails closed (sha mismatch)
    return manifest


def prepare_trivy(cache_dir: str) -> None:
    for flag in ("--download-db-only", "--download-java-db-only"):
        r = _run(["trivy", "image", flag, "-q", "--cache-dir", cache_dir], 1800)
        if r.returncode != 0:
            raise VulnError(f"trivy {flag} exited with code {r.returncode}")


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="python -m invariant_assessment.prepare")
    p.add_argument("--cache-dir", default=os.environ.get(CACHE_ENV))
    p.add_argument("--feeds-only", action="store_true", help="skip the Trivy DB downloads")
    try:
        args = p.parse_args(argv)
    except SystemExit as e:
        return int(e.code or 0)
    if not args.cache_dir:
        print(f"prepare: usage error: set {CACHE_ENV} or pass --cache-dir", file=sys.stderr)
        return 2
    try:
        manifest = prepare_feeds(args.cache_dir)
        if not args.feeds_only:
            prepare_trivy(args.cache_dir)
    except Exception as e:
        msg = str(e) if isinstance(e, VulnError) else f"unexpected error ({type(e).__name__})"
        print(f"prepare: error: {msg}", file=sys.stderr)
        if os.environ.get("INVARIANT_DEBUG") == "1":
            traceback.print_exc()
        return 4
    print(json.dumps(manifest, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
