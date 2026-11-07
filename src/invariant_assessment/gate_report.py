"""INV-105: human-readable gate output (terminal table, Markdown for GitHub / Jenkins, --out-dir files).

Every field that comes from the target (evidence, package, version, ids) goes through `md()` (Markdown) or
`clean()` (terminal): ANSI sequences and control characters are removed, line breaks become spaces, and
Markdown punctuation is escaped. Nothing here reads process data, credentials or facts: only gate fields.
"""

import os
import re
from pathlib import Path

from invariant_assessment import vuln
from invariant_assessment.cli import UsageError
from invariant_assessment.gate_explain import phrase

MAX_REASONS = 20
_ANSI = re.compile(r"\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07\x1b]*(?:\x07|\x1b\\)?|.)")
_CTL = re.compile(r"[\x00-\x1f\x7f-\x9f]")
_MD = re.compile(r"([\\`|<>\[\]*_])")


def clean(v) -> str:
    return " ".join(_CTL.sub(" ", _ANSI.sub("", str(v))).split())


def md(v) -> str:
    return _MD.sub(r"\\\1", clean(v))


def _plural(n: int, one: str, many: str | None = None) -> str:
    return f"{n:,} {one if n == 1 else (many or one + 's')}"


def headline(out: dict) -> str:
    n = len(out["reasons"])
    return f"❌ Deploy blocked: {_plural(n, 'problem')}" if out["decision"] == "block" else "✅ Deploy allowed"


def contrast(out: dict) -> str:
    x = sum(1 for r in out["reasons"] if r["type"] == "cve")
    y = len(out["reasons"]) - x
    s = f"Trivy reported {_plural(out['total_findings'], 'finding')} ({_plural(out['unique_cves'], 'unique CVE')}) → Invariant blocks on {x:,}."
    return s + (f" Plus {_plural(y, 'configuration issue')} Trivy doesn't check." if y else "")


def _kev_by_cve(out: dict) -> dict[str, list[dict]]:
    m: dict[str, list[dict]] = {}
    for f in out["findings"]:
        if f["in_kev"]:
            m.setdefault(f["cve"], []).append(f)
    return m


def _pkg_phrases(fs: list[dict]) -> list[str]:
    return sorted({f"{f['package']} {f.get('installed_version') or '?'}: {phrase(f['context_reason'])}" for f in fs})


def _impact(r: dict) -> str:
    if r["type"] == "check":
        return r["explanation"]["exploit"]
    return ("Attackers are already exploiting this flaw, and a process that listens on the network uses the vulnerable code."
            if r["state"] == "exposed" else
            "Attackers are already exploiting this flaw, and we can't rule out that the vulnerable code is reachable from the network.")


def _detail(r: dict, kev: dict) -> list[str]:
    x = r["explanation"]
    d = [f"Where: {md(x['where'])}"]
    if r["type"] == "cve":
        f0 = kev[r["id"]][0]
        n = lambda k: "n/a" if f0.get(k) is None else f0[k]  # noqa: E731
        d += [f"CVSS: {md(n('cvss_v3_score'))} (severity {md(n('severity'))}); EPSS: {md(n('epss_score'))}",
              f"On the CISA KEV list since: {md(n('kev_date_added'))}; ransomware use: {md(n('kev_known_ransomware_campaign_use'))}"]
        d += [f"Exposure: {md(p)}" for p in _pkg_phrases(kev[r["id"]])]
    d += [f"Why: {md(x['why'])}", f"How it is exploited: {md(x['exploit'])}", f"Fix: {md(x['fix'])}"]
    return d


def _classes(out: dict) -> list[str]:
    """One line per class of non-blocking findings, with its count. KEV CVEs of a class are already reasons."""
    NB = "not blocking, none are actively exploited"
    specs = (
        (lambda f: f["exposure"] == "unknown" and f["context_reason"] == "interpreted_code", "could not be ruled out (scripts)", "; ", NB),
        (lambda f: f["exposure"] == "unknown" and f["context_reason"] in ("not_in_dpkg", "no_dpkg"),
         "in language packages could not be checked", "; ", NB),
        (lambda f: f["exposure"] == "unknown" and f["context_reason"] == "unreadable",
         "could not be checked (process data could not be read)", "; ", NB),
        (lambda f: f["exposure"] == "exposed", "in network-facing code", ", ", "none actively exploited"),
    )
    lines = []
    for pred, what, sep, tail in specs:
        cls = [f for f in out["findings"] if pred(f)]
        kev = len({f["cve"] for f in cls if f["in_kev"]})
        if cls:
            if kev:
                tail = f"{_plural(kev, 'actively exploited CVE')} listed above, the rest are not blocking"
            lines.append(f"{_plural(len(cls), 'finding')} {what}{sep}{tail}")
    return lines


def render_markdown(out: dict, jenkins: bool = False) -> str:
    """GitHub variant uses <details>; the Jenkins variant has no HTML at all (nested list items instead)."""
    kev = _kev_by_cve(out)
    reasons = out["reasons"]
    L = [headline(out), "", contrast(out), ""]
    for i, r in enumerate(reasons[:MAX_REASONS], 1):
        L += [f"### {i}. {md(r['title'])}", "", _impact(r), "", f"**Action:** {md(r['action'])}", ""]
        det = _detail(r, kev)
        if jenkins:
            L += ["- Technical detail"] + [f"  - {d}" for d in det]
        else:
            L += ["<details><summary>Technical detail</summary>", ""] + [f"- {d}" for d in det] + ["", "</details>"]
        L.append("")
    if len(reasons) > MAX_REASONS:
        L += [f"…and {len(reasons) - MAX_REASONS} more", ""]
    blocking = {r["id"] for r in reasons if r["type"] == "cve"}
    visible = [(c, fs) for c, fs in kev.items() if c not in blocking]
    if visible:
        L += ["## Visible, not blocking", ""]
        for c, fs in visible[:MAX_REASONS]:
            why = "covered by an exception" if any(f["exposure"] in ("exposed", "unknown") for f in fs) \
                else "; ".join(sorted({phrase(f["context_reason"]) for f in fs}))
            L.append(f"- {c} in {md(', '.join(sorted({f['package'] for f in fs})))}: {why}")
        if len(visible) > MAX_REASONS:
            L.append(f"- …and {len(visible) - MAX_REASONS} more")
        L.append("")
    cls = _classes(out)
    if cls:
        L += ["## Other findings", ""] + [f"- {c}" for c in cls] + [""]
    if out["exceptions"]:
        L += ["## Exceptions", ""]
        L += [f"- {md(e['status'])}: {md(e['id'])}{' ' + md(e['package']) if e['package'] else ''}, owner {md(e['owner'])}, "
              f"expires {md(e['expires'])}{' (' + md(e['note']) + ')' if e['note'] else ''}" for e in out["exceptions"]] + [""]
    L += ["## Assumptions", ""] + [f"{i}. {md(a)}" for i, a in enumerate(out["assumptions"], 1)]
    if out.get("warnings"):
        L += ["", "## Warnings", ""] + [f"- {md(w)}" for w in out["warnings"]]
    return "\n".join(L) + "\n"


def error_markdown(message: str) -> str:
    return f"⛔ Gate could not run (pipeline error): deploy blocked\n\n{md(message)}\n"


def render_table(out: dict) -> str:
    kev = _kev_by_cve(out)
    c = clean
    L = [headline(out), contrast(out), ""]
    for i, r in enumerate(out["reasons"][:MAX_REASONS], 1):
        L += [f"  {i}. {c(r['title'])}", f"     Action: {c(r['action'])}"]
    if len(out["reasons"]) > MAX_REASONS:
        L.append(f"  …and {len(out['reasons']) - MAX_REASONS} more")
    L += ["", f"DECISION: {out['decision'].upper()}  target: {c(out['target'])}  image: {c(out['image_ref']['ref'])}"]
    for r in out["reasons"]:
        pk = f" [{c(', '.join(r['packages']))}]" if r["packages"] else ""
        why = r["reason"] if r["type"] == "check" else "CVE in CISA KEV; " + "; ".join(_pkg_phrases(kev[r["id"]]))
        L.append(f"  BLOCK {r['type']} {c(r['id'])}{pk} {r['state']}: {c(why)}")
        L += [f"      {k}: {c(r['explanation'][key])}" for k, key in (("Where", "where"), ("Why", "why"), ("Exploit", "exploit"), ("Fix", "fix"))]
    L += ["", "CVEs in CISA KEV (all):"]
    L += [f"  {c(cve)}  {c('; '.join(_pkg_phrases(fs)))}" for cve, fs in kev.items()] or ["  (none)"]
    L += ["", f"findings={out['total_findings']} unique_cves={out['unique_cves']} unique_cves_in_kev={out['unique_cves_in_kev']} "
              f"kev_catalog={c(out['kev_catalog_version'])} trivy_db_age_days={out['db_age_days']}", "", "exceptions:"]
    L += [f"  {e['status']:<8} {c(e['id'])}{' ' + c(e['package']) if e['package'] else ''} owner={c(e['owner'])} expires={c(e['expires'])}"
          f"{' - ' + c(e['note']) if e['note'] else ''}" for e in out["exceptions"]] or ["  (none)"]
    L += ["", "assumptions:"] + [f"  {i}. {c(a)}" for i, a in enumerate(out["assumptions"], 1)]
    return "\n".join(L)


def check_out_dir(path: str) -> Path:
    """Refuse (UsageError, exit 2) the Trivy cache or anything inside it: the cache is read-only."""
    d = Path(path).resolve()
    cache = os.environ.get(vuln.CACHE_ENV)
    if cache:
        cp = Path(cache).resolve()
        if d == cp or cp in d.parents:
            raise UsageError("--out-dir must not be the Trivy cache or inside it (the cache is read-only)")
    return d


def write_atomic(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    try:
        tmp.write_text(text, encoding="utf-8")
        os.replace(tmp, path)
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise
