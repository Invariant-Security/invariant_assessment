"""`invariant gate` (INV-84): assess + Trivy + KEV/EPSS + container context -> pass/block.

Blocks (exit 1) when (a) a critical check of the catalog has effective_status FAIL or
NOT_ASSESSED (NOT_APPLICABLE does not block), or (b) a CVE listed in the CISA KEV has a
package whose exposure is `exposed` or `unknown`. EPSS only informs and orders.
Exceptions come from `.invariant-exceptions.yaml`. Only --docker is supported for now.
All collection is reused (cli.assess, vuln.scan, enrich, context); nothing here reads the target.
"""

import os
import re
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

import yaml

from invariant_assessment import context, enrich, vuln
from invariant_assessment.cli import UsageError, load_catalog

EXCEPTIONS_FILE = ".invariant-exceptions.yaml"
MAX_EXCEPTION_DAYS = 90
_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")
_FIELDS = ("id", "justification", "owner", "expires")
BLOCKING_EXPOSURE = ("exposed", "unknown")


def load_exceptions(path: str | None, today: date) -> list[dict]:
    """Every entry with a `status`: valid | expired | invalid (+ `note`). Unreadable or
    malformed file -> UsageError (exit 2)."""
    if path is None:
        if not Path(EXCEPTIONS_FILE).exists():
            return []
        path = EXCEPTIONS_FILE
    try:
        data = yaml.safe_load(Path(path).read_text())
    except (OSError, UnicodeDecodeError, yaml.YAMLError) as e:
        raise UsageError(f"cannot read the exceptions file ({type(e).__name__})") from e
    if data is None:
        return []
    items = data.get("exceptions") if isinstance(data, dict) else None
    if not isinstance(items, list):
        raise UsageError("exceptions file must be a mapping with an `exceptions:` list")
    out = []
    for raw in items:
        e = {"id": None, "package": None, "justification": None, "owner": None, "expires": None, "status": "invalid", "note": None}
        out.append(e)
        if not isinstance(raw, dict):
            e["note"] = "entry is not a mapping"
            continue
        e.update({k: (str(raw[k]) if raw.get(k) is not None else None) for k in (*_FIELDS, "package")})
        missing = [k for k in _FIELDS if not (e[k] and e[k].strip())]
        if not missing and _CVE_RE.match(e["id"]) and not (e["package"] or "").strip():
            missing = ["package"]
        if missing:
            e["note"] = "missing field(s): " + ", ".join(missing)
            continue
        try:
            exp = raw["expires"] if isinstance(raw["expires"], date) and not isinstance(raw["expires"], datetime) \
                else date.fromisoformat(str(raw["expires"]))
        except ValueError:
            e["note"] = "expires is not an ISO date"
            continue
        e["expires"] = exp.isoformat()
        if exp > today + timedelta(days=MAX_EXCEPTION_DAYS):
            e["note"] = f"expires is more than {MAX_EXCEPTION_DAYS} days away"
        elif exp < today:
            e["status"], e["note"] = "expired", "expired; ignored"
        else:
            e["status"] = "valid"
    return out


def decide(results: list[dict], findings: list[dict], catalog: dict, exceptions: list[dict]) -> tuple[list[dict], list[dict]]:
    """(reasons still blocking, exceptions report). Pure function."""
    reasons = []
    for r in results:
        if catalog.get(r["check_id"], {}).get("critical") and r["effective_status"] in ("FAIL", "NOT_ASSESSED"):
            reasons.append({"type": "check", "id": r["check_id"], "packages": None, "state": r["effective_status"],
                            "reason": f"critical check {r['effective_status']}"})
    by_cve: dict[str, list[dict]] = {}
    for f in findings:
        if f["in_kev"] and f["exposure"] in BLOCKING_EXPOSURE:
            by_cve.setdefault(f["cve"], []).append(f)
    for cve, fs in by_cve.items():  # findings are already ordered (epss desc)
        state = "exposed" if any(f["exposure"] == "exposed" for f in fs) else "unknown"
        reasons.append({"type": "cve", "id": cve, "packages": sorted({f["package"] for f in fs}), "state": state,
                        "reason": "CVE in CISA KEV; " + "; ".join(sorted({f"{f['package']}: {f['exposure']} ({f['context_reason']})" for f in fs}))})
    report, kept = [], []
    valid = [e for e in exceptions if e["status"] == "valid"]
    for rs in reasons:
        if rs["type"] == "check":
            hit = [e for e in valid if e["id"] == rs["id"]]
        else:
            covered = {e["package"] for e in valid if e["id"] == rs["id"]}
            hit = [e for e in valid if e["id"] == rs["id"]] if set(rs["packages"]) <= covered else []
        if hit:
            for e in hit:
                e["status"] = "applied"
        else:
            kept.append(rs)
    for e in exceptions:
        if e["status"] == "valid":
            partial = any(rs["type"] == "cve" and rs["id"] == e["id"] for rs in kept)
            e["status"], e["note"] = ("partial", "does not cover every exposed/unknown package of the CVE") if partial \
                else ("unused", "matches no blocking reason")
        report.append(e)
    return kept, report


def gate(args) -> dict:
    from invariant_assessment import cli

    if args.ssh or args.local:
        raise UsageError("gate --ssh/--local: ainda não suportado (use --docker)")
    cache = os.environ.get(vuln.CACHE_ENV)
    if not cache:
        raise UsageError(f"set {vuln.CACHE_ENV} (read-only Trivy/feeds cache)")
    now = datetime.now(timezone.utc)
    exceptions = load_exceptions(args.exceptions, now.date())  # malformed file: exit 2 before any work
    feeds = enrich.load_feeds(cache, now)  # fail fast, before the slow scan
    catalog, _ = load_catalog()
    out = cli.assess(args)
    report = vuln.scan(None, args.docker, cache, now)
    report["findings"] = enrich.enrich(report["findings"], feeds)
    context.collect(report, args.docker)
    findings = report.pop("findings")
    reasons, exc_report = decide(out["results"], findings, catalog, exceptions)
    warnings = [w for w in (report["db_age_warning"], feeds["warning"]) if w]
    warnings += [f"exception {e['id']} {e['status']}: {e['note']}" for e in exc_report if e["status"] in ("expired", "invalid")]
    return {
        "decision": "block" if reasons else "pass",
        "reasons": reasons,
        "exceptions": exc_report,
        "warnings": warnings,
        **out,
        **report,
        "kev_catalog_version": feeds["kev_catalog_version"],
        "feeds": feeds["feeds"],
        "feeds_age_warning": feeds["warning"],
        "unique_cves_in_kev": len({f["cve"] for f in findings if f["in_kev"]}),
        "findings": findings,
    }


def render_table(out: dict) -> str:
    L = [f"DECISION: {out['decision'].upper()}  target: {out['target']}  image: {out['image_ref']['ref']}"]
    for r in out["reasons"]:
        pk = f" [{', '.join(r['packages'])}]" if r["packages"] else ""
        L.append(f"  BLOCK {r['type']} {r['id']}{pk} {r['state']}: {r['reason']}")
    L += ["", "CVEs in CISA KEV (all):"]
    seen = {}
    for f in out["findings"]:
        if f["in_kev"]:
            seen.setdefault(f["cve"], []).append(f"{f['package']}={f['exposure']}/{f['context_reason']}")
    L += [f"  {cve}  {', '.join(p)}" for cve, p in seen.items()] or ["  (none)"]
    L += ["", f"findings={out['total_findings']} unique_cves={out['unique_cves']} unique_cves_in_kev={out['unique_cves_in_kev']} "
              f"kev_catalog={out['kev_catalog_version']} trivy_db_age_days={out['db_age_days']}", "", "exceptions:"]
    L += [f"  {e['status']:<8} {e['id']}{' ' + e['package'] if e['package'] else ''} owner={e['owner']} expires={e['expires']}"
          f"{' - ' + e['note'] if e['note'] else ''}" for e in out["exceptions"]] or ["  (none)"]
    return "\n".join(L)
