"""`invariant gate` (INV-84): assess + Trivy + KEV/EPSS + container context -> pass/block.

Blocks (exit 1) when (a) a critical check of the catalog has effective_status FAIL or
NOT_ASSESSED (NOT_APPLICABLE does not block), or (b) a CVE listed in the CISA KEV has a
package whose exposure is `exposed` or `unknown`. EPSS only informs and orders.
Exceptions come from `.invariant-exceptions.yaml`. Only --docker is supported for now.
All collection is reused (cli.assess, vuln.scan, enrich, context); nothing here reads the target.
"""

import json
import os
import re
import xml.etree.ElementTree as ET
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

import yaml

from invariant_assessment import context, enrich, gate_explain, vuln
from invariant_assessment.cli import UsageError, load_catalog
from invariant_assessment.gate_report import render_markdown, render_table, write_atomic  # noqa: F401

EXCEPTIONS_FILE = ".invariant-exceptions.yaml"
MAX_EXCEPTION_DAYS = 90
_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")
_FIELDS = ("id", "justification", "owner", "expires")
BLOCKING_EXPOSURE = ("exposed", "unknown")
_XML_BAD = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\ufffe\uffff]")
OUT_FILES = ("invariant-gate.json", "invariant-gate.junit.xml", "invariant-gate.md", "invariant-gate.jenkins.md")


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


def decide(results: list[dict], findings: list[dict], catalog: dict, exceptions: list[dict], target: str = "target") -> tuple[list[dict], list[dict]]:
    """(reasons still blocking, exceptions report). Pure function."""
    reasons = []
    for r in results:
        if catalog.get(r["check_id"], {}).get("critical") and r["effective_status"] in ("FAIL", "NOT_ASSESSED"):
            reasons.append({"type": "check", "id": r["check_id"], "packages": None, "state": r["effective_status"],
                            "reason": f"critical check {r['effective_status']}",
                            "explanation": gate_explain.explain_check(r["check_id"], r["effective_status"], r, target),
                            **dict(zip(("title", "action"), gate_explain.plain_check(r["check_id"], r["effective_status"])))})
    present = {r["check_id"] for r in results}
    for cid in sorted(c for c, m in catalog.items() if m.get("critical") and c not in present):  # fail closed
        reasons.append({"type": "check", "id": cid, "packages": None, "state": "NOT_ASSESSED",
                        "reason": "critical check missing from results",
                        "explanation": gate_explain.explain_check(cid, "NOT_ASSESSED", None, target),
                        **dict(zip(("title", "action"), gate_explain.plain_check(cid, "NOT_ASSESSED")))})
    by_cve: dict[str, list[dict]] = {}
    for f in findings:
        if f["in_kev"] and f["exposure"] in BLOCKING_EXPOSURE:
            by_cve.setdefault(f["cve"], []).append(f)
    for cve, fs in by_cve.items():  # findings are already ordered (epss desc)
        state = "exposed" if any(f["exposure"] == "exposed" for f in fs) else "unknown"
        reasons.append({"type": "cve", "id": cve, "packages": sorted({f["package"] for f in fs}), "state": state,
                        "reason": "CVE in CISA KEV; " + "; ".join(sorted({f"{f['package']}: {f['exposure']} ({f['context_reason']})" for f in fs})),
                        "explanation": gate_explain.explain_cve(cve, fs, target),
                        **dict(zip(("title", "action"), gate_explain.plain_cve(cve, fs, state)))})
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
    reasons, exc_report = decide(out["results"], findings, catalog, exceptions, args.docker)
    warnings = [w for w in (report["db_age_warning"], feeds["warning"]) if w]
    warnings += [f"exception {e['id']} {e['status']}: {e['note']}" for e in exc_report if e["status"] in ("expired", "invalid")]
    return {
        "decision": "block" if reasons else "pass",
        "reasons": reasons,
        "assumptions": gate_explain.ASSUMPTIONS,
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


def render_junit(out: dict, catalog: dict) -> str:
    """JUnit XML (Jenkins): one testcase per critical check and per KEV CVE found. Same decision as
    the exit code. Only fields already in the gate output (no process data, credentials or facts)."""
    reasons = {(r["type"], r["id"]): r for r in out["reasons"]}
    applied = {e["id"]: e for e in out["exceptions"] if e["status"] == "applied"}
    status = {r["check_id"]: r["effective_status"] for r in out["results"]}
    cases = []

    def case(cls, name, reason=None, skipped=False, note=None):
        tc = ET.Element("testcase", classname=cls, name=name)
        if reason:
            x = reason["explanation"]
            body = "\n".join(f"{k}: {x[key]}" for k, key in (("Where", "where"), ("Why", "why"), ("Exploit", "exploit"), ("Fix", "fix")))
            ET.SubElement(tc, "failure", message=reason["reason"], type=reason["state"]).text = body
        elif skipped:
            ET.SubElement(tc, "skipped", message="NOT_APPLICABLE")
        e = applied.get(name)
        if note or e:
            ET.SubElement(tc, "system-out").text = "\n".join(
                ([note] if note else []) + ([f"exception applied: id={e['id']} owner={e['owner']} expires={e['expires']}"] if e else []))
        cases.append((tc, bool(reason)))

    for cid in sorted(c for c, m in catalog.items() if m.get("critical")):
        case("invariant.checks", cid, reasons.get(("check", cid)), status.get(cid) == "NOT_APPLICABLE", f"status: {status.get(cid, 'missing')}")
    kev: dict[str, list[dict]] = {}
    for f in out["findings"]:
        if f["in_kev"]:
            kev.setdefault(f["cve"], []).append(f)
    for cve, fs in kev.items():
        case("invariant.kev", cve, reasons.get(("cve", cve)),
             note="; ".join(sorted({f"{f['package']}: {f['exposure']} ({f['context_reason']})" for f in fs})))
    n_fail = sum(1 for _, bad in cases if bad)
    suite = ET.Element("testsuite", name="invariant-gate", tests=str(len(cases)), failures=str(n_fail), errors="0",
                       skipped=str(sum(1 for tc, _ in cases if tc.find("skipped") is not None)))
    props = ET.SubElement(suite, "properties")
    for k, v in (("decision", out["decision"]), ("target", out["target"]), ("image_ref", out["image_ref"]["ref"]),
                 ("invariant_version", out.get("invariant_version")), ("catalog_version", out.get("catalog_version")),
                 ("trivy_version", out.get("trivy_version")), ("kev_catalog_version", out["kev_catalog_version"]),
                 ("run_id", out.get("run_id"))):
        ET.SubElement(props, "property", name=k, value="" if v is None else str(v))
    suite.extend(tc for tc, _ in cases)
    root = ET.Element("testsuites", tests=suite.get("tests"), failures=suite.get("failures"))
    root.append(suite)
    for el in root.iter():  # control characters would make the XML unparseable
        el.text = _XML_BAD.sub("", el.text) if el.text else el.text
        for k, v in list(el.attrib.items()):
            el.set(k, _XML_BAD.sub("", v))
    ET.indent(root)
    return ET.tostring(root, encoding="unicode", xml_declaration=False)


def write_reports(out_dir: Path, out: dict, catalog: dict) -> None:
    """The four fixed-name files of one run (each written atomically)."""
    texts = (json.dumps(out, indent=2), render_junit(out, catalog), render_markdown(out), render_markdown(out, jenkins=True))
    for name, text in zip(OUT_FILES, texts):
        write_atomic(out_dir / name, text)
