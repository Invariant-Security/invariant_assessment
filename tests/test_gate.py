"""INV-84 `invariant gate`: decision rules, exceptions file, exit codes (no Docker, no Trivy)."""

import json
from datetime import date, timedelta

import pytest

from invariant_assessment import cli, context, enrich, gate, gate_explain, vuln
from invariant_assessment.cli import UsageError

MARKER = "SEGREDO-MARCADO-gate-5c2e"
TODAY = date.today()
ISO = lambda d: (TODAY + timedelta(days=d)).isoformat()  # noqa: E731
CAT = {"crit": {"critical": True}, "other": {"critical": False}}


def res(cid, eff):
    return {"check_id": cid, "status": "PASS", "effective_status": eff}


OK = [res("crit", "PASS")]


def fnd(cve, pkg, exposure, kev=True, epss=0.0, reason="x"):
    return {"cve": cve, "package": pkg, "in_kev": kev, "exposure": exposure, "context_reason": reason, "epss_score": epss}


def exc(id, pkg=None, expires=None, **kw):
    return {"id": id, "package": pkg, "justification": "j", "owner": "o", "expires": expires or ISO(10), "status": "valid", "note": None, **kw}


def ids(reasons):
    return [(r["type"], r["id"]) for r in reasons]


@pytest.mark.parametrize("eff,blocks", [("FAIL", True), ("NOT_ASSESSED", True), ("PASS", False), ("NOT_APPLICABLE", False)])
def test_critical_check_rule(eff, blocks):
    assert bool(gate.decide([res("crit", eff)], [], CAT, [])[0]) is blocks


def test_critical_check_missing_from_results_blocks_and_can_be_excepted():
    (r,), _ = gate.decide([res("other", "PASS")], [], CAT, [])
    assert (r["id"], r["state"], r["reason"]) == ("crit", "NOT_ASSESSED", "critical check missing from results")
    assert gate.decide([], [], CAT, [exc("crit")])[0] == []


def test_non_critical_and_unknown_checks_never_block():
    assert gate.decide(OK + [res("other", "FAIL"), res("nope", "FAIL")], [], CAT, [])[0] == []


@pytest.mark.parametrize("exposure,blocks", [("exposed", True), ("unknown", True), ("not_exposed", False)])
def test_kev_rule(exposure, blocks):
    assert bool(gate.decide(OK, [fnd("CVE-2026-1111", "p", exposure)], CAT, [])[0]) is blocks


def test_epss_and_non_kev_never_block():
    f = [fnd("CVE-2026-1111", "p", "exposed", kev=False, epss=0.99), fnd("CVE-2026-2222", "p", "unknown", kev=False)]
    assert gate.decide(OK, f, CAT, [])[0] == []


def test_one_reason_per_cve_grouping_packages():
    f = [fnd("CVE-2026-1111", "libbrotli1", "exposed"), fnd("CVE-2026-1111", "libbrotli-dev", "exposed"),
         fnd("CVE-2026-1111", "z", "not_exposed")]
    (r,), _ = gate.decide(OK, f, CAT, [])
    assert r["packages"] == ["libbrotli-dev", "libbrotli1"] and r["state"] == "exposed"


def test_exception_applied_check_and_cve():
    f = [fnd("CVE-2026-1111", "a", "exposed"), fnd("CVE-2026-1111", "b", "unknown")]
    e = [exc("crit"), exc("CVE-2026-1111", "a"), exc("CVE-2026-1111", "b")]
    reasons, rep = gate.decide([res("crit", "FAIL")], f, CAT, e)
    assert reasons == [] and [x["status"] for x in rep] == ["applied"] * 3


def test_cve_exception_covering_only_one_package_does_not_remove_reason():
    f = [fnd("CVE-2026-1111", "a", "exposed"), fnd("CVE-2026-1111", "b", "exposed")]
    reasons, rep = gate.decide(OK, f, CAT, [exc("CVE-2026-1111", "a")])
    assert ids(reasons) == [("cve", "CVE-2026-1111")] and rep[0]["status"] == "partial"


def test_unused_exception_is_reported():
    assert gate.decide(OK, [], CAT, [exc("crit")])[1][0]["status"] == "unused"


def write(tmp_path, text):
    p = tmp_path / "ex.yaml"
    p.write_text(text)
    return str(p)


def test_load_exceptions_statuses(tmp_path):
    p = write(tmp_path, f"""
exceptions:
  - {{id: crit, justification: j, owner: o, expires: {ISO(30)}}}
  - {{id: crit, justification: j, owner: o, expires: {ISO(-1)}}}
  - {{id: crit, justification: j, owner: o, expires: {ISO(91)}}}
  - {{id: crit, justification: j, owner: o, expires: {ISO(90)}}}
  - {{id: crit, justification: j, owner: o, expires: not-a-date}}
  - {{id: crit, justification: j, expires: {ISO(5)}}}
  - {{id: CVE-2026-1111, justification: j, owner: o, expires: {ISO(5)}}}
  - {{id: CVE-2026-1111, package: p, justification: j, owner: o, expires: "{ISO(5)}"}}
  - just a string
""")
    assert [e["status"] for e in gate.load_exceptions(p, TODAY)] == \
        ["valid", "expired", "invalid", "valid", "invalid", "invalid", "invalid", "valid", "invalid"]


@pytest.mark.parametrize("text", ["exceptions: [unclosed", "- a\n- b\n", "exceptions: nope\n"])
def test_malformed_exceptions_file(tmp_path, text):
    with pytest.raises(UsageError):
        gate.load_exceptions(write(tmp_path, text), TODAY)
    with pytest.raises(UsageError):
        gate.load_exceptions(str(tmp_path / "missing.yaml"), TODAY)


def test_default_exceptions_file_only_if_present(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    assert gate.load_exceptions(None, TODAY) == []
    (tmp_path / gate.EXCEPTIONS_FILE).write_text(f"exceptions:\n  - {{id: crit, justification: j, owner: o, expires: {ISO(1)}}}\n")
    assert len(gate.load_exceptions(None, TODAY)) == 1


# --- CLI wiring and exit codes ----------------------------------------------------------


def run(capsys, *argv):
    rc = cli.main(["gate", *argv])
    cap = capsys.readouterr()
    return rc, cap.out, cap.err


@pytest.fixture
def wired(monkeypatch, tmp_path):
    """Everything below the decision stubbed; knobs in the returned dict."""
    st = {"results": [res("crit", "PASS")], "findings": [], "feeds_error": None}
    monkeypatch.setenv(vuln.CACHE_ENV, str(tmp_path))
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(cli, "assess", lambda a: {"results": st["results"], "target": a.docker, "transport": "docker"})

    def feeds(cache, now):
        if st["feeds_error"]:
            raise vuln.VulnError(st["feeds_error"])
        return {"kev_catalog_version": "v", "feeds": {}, "warning": None}

    monkeypatch.setattr(enrich, "load_feeds", feeds)
    monkeypatch.setattr(cli, "load_catalog", lambda: (CAT, "x"))
    monkeypatch.setattr(gate, "load_catalog", lambda: (CAT, "x"))
    monkeypatch.setattr(vuln, "scan", lambda *a: {"image_ref": {"ref": "r", "kind": "image_id"}, "db_age_warning": None,
                                                  "db_age_days": 0.1, "total_findings": len(st["findings"]), "unique_cves": 1,
                                                  "findings": list(st["findings"])})
    monkeypatch.setattr(enrich, "enrich", lambda f, feeds: f)
    monkeypatch.setattr(context, "collect", lambda report, c: report)
    return st


def test_pass_and_block_exit_codes_and_outputs(capsys, wired):
    rc, out, _ = run(capsys, "--docker", "c", "--format", "json")
    assert rc == 0 and json.loads(out)["decision"] == "pass" and json.loads(out)["reasons"] == []
    wired["results"] = [res("crit", "NOT_ASSESSED")]
    wired["findings"] = [fnd("CVE-2026-1111", "p", "not_exposed")]
    rc, out, _ = run(capsys, "--docker", "c", "--format", "json")
    d = json.loads(out)
    assert rc == 1 and d["decision"] == "block" and ids(d["reasons"]) == [("check", "crit")]
    assert d["findings"] and d["results"] and d["unique_cves_in_kev"] == 1
    rc, out, _ = run(capsys, "--docker", "c")
    assert rc == 1 and out.startswith("❌ Deploy blocked: 1 problem") and "DECISION: BLOCK" in out and "CVE-2026-1111" in out  # KEV listed though not blocking


def test_exception_file_turns_block_into_pass_and_is_reported(capsys, wired, tmp_path):
    wired["results"] = [res("crit", "FAIL")]
    p = write(tmp_path, f"exceptions:\n  - {{id: crit, justification: j, owner: o, expires: {ISO(5)}}}\n")
    rc, out, _ = run(capsys, "--docker", "c", "--format", "json", "--exceptions", p)
    d = json.loads(out)
    assert rc == 0 and d["exceptions"][0]["status"] == "applied"
    assert "applied" in run(capsys, "--docker", "c", "--exceptions", p)[1]


def test_expired_exception_still_blocks_with_warning(capsys, wired, tmp_path):
    wired["results"] = [res("crit", "FAIL")]
    p = write(tmp_path, f"exceptions:\n  - {{id: crit, justification: j, owner: o, expires: {ISO(-2)}}}\n")
    rc, out, err = run(capsys, "--docker", "c", "--format", "json", "--exceptions", p)
    assert rc == 1 and json.loads(out)["exceptions"][0]["status"] == "expired" and "expired" in err


@pytest.mark.parametrize("argv", [["--ssh", "u@h"], ["--local"]])
def test_ssh_and_local_not_supported_exit_2(capsys, wired, argv):
    rc, out, err = run(capsys, *argv)
    assert rc == 2 and "ainda não suportado" in err and "pass" not in (out + err).lower()


def test_malformed_exceptions_exit_2(capsys, wired, tmp_path):
    rc, out, _ = run(capsys, "--docker", "c", "--exceptions", write(tmp_path, "exceptions: [x"))
    assert rc == 2 and "pass" not in out.lower()


def test_missing_cache_env_exit_2(capsys, wired, monkeypatch):
    monkeypatch.delenv(vuln.CACHE_ENV)
    assert run(capsys, "--docker", "c")[0] == 2


def test_old_or_missing_feed_exit_4_before_scan(capsys, wired, monkeypatch):
    wired["feeds_error"] = "KEV feed is 8.0 days old (limit 7); run prepare"
    monkeypatch.setattr(vuln, "scan", lambda *a: pytest.fail("scan must not run"))
    rc, out, err = run(capsys, "--docker", "c")
    assert rc == 4 and "days old" in err and "pass" not in (out + err).lower()


def test_transport_error_exit_3(capsys, wired, monkeypatch):
    def boom(a):
        raise cli.TransportUnreachableError("no container")
    monkeypatch.setattr(cli, "assess", boom)
    rc, out, _ = run(capsys, "--docker", "c")
    assert rc == 3 and out == ""


def test_marked_process_data_never_in_output(capsys, wired, monkeypatch):
    monkeypatch.setattr(context, "collect", lambda report, c: report)
    monkeypatch.setattr(cli, "assess", lambda a: {"results": [res("crit", "PASS")], "target": "c", "transport": "docker"})
    wired["findings"] = [fnd("CVE-2026-1111", "p", "exposed")]
    for fmt in ("json", "table", "junit"):
        rc, out, err = run(capsys, "--docker", "c", "--format", fmt)
        assert rc == 1 and MARKER not in out + err
        assert "Where:" in out or fmt == "json"
    # the real probe parser keeps executable paths in memory only
    probe = f"PROC ok\nP\nM /opt/{MARKER}/lib.so\nS 11\n"
    rep = context.add_context({"findings": [{"package": "p", "installed_version": "1"}]}, probe, "DPKG ok\nPKG p ok 1\n")
    assert MARKER not in json.dumps(rep)


# --- INV-85 explanations ---------------------------------------------------------------

REAL_CAT, _ = cli.load_catalog()
CRITICAL = sorted(c for c, m in REAL_CAT.items() if m["critical"])
FIELDS = {"where", "why", "exploit", "fix"}


def test_every_critical_check_has_nonempty_own_text():
    assert len(CRITICAL) == 15 and set(CRITICAL) == set(gate_explain.CHECK_TEXT)
    for cid in CRITICAL:
        (r,), _ = gate.decide([{**res(cid, "FAIL"), "evidence": "mode 0666"}], [], {cid: {"critical": True}}, [], "img")
        e = r["explanation"]
        assert set(e) == FIELDS and all(v.strip() for v in e.values()) and "img" in e["where"] and "mode 0666" in e["where"]


@pytest.mark.parametrize("missing", [True, False])
def test_not_assessed_explains_fail_closed(missing):
    results = [] if missing else [{**res("crit", "NOT_ASSESSED"), "evidence": "exec denied"}]
    (r,), _ = gate.decide(results, [], CAT, [], "c1")
    assert "fails closed" in r["explanation"]["why"] and "privilege" in r["explanation"]["fix"]


def test_cve_explanation_with_and_without_fixed_version_and_exposure():
    base = {"installed_version": "1.0", "severity": "CRITICAL", "cvss_v3_score": 9.8, "epss_score": 0.5,
            "kev_date_added": "2026-01-02", "kev_known_ransomware_campaign_use": "Known"}
    (a,), _ = gate.decide(OK, [{**fnd("CVE-2026-1111", "p", "exposed"), **base, "fixed_version": "1.1"}], CAT, [], "img")
    assert "1.1" in a["explanation"]["fix"] and "p 1.0" in a["explanation"]["where"]
    assert "exposed:" in a["explanation"]["why"] and "2026-01-02" in a["explanation"]["why"] and "9.8" in a["explanation"]["why"]
    (b,), _ = gate.decide(OK, [{**fnd("CVE-2026-1111", "p", "unknown"), **base, "fixed_version": None}], CAT, [], "img")
    assert "unknown:" in b["explanation"]["why"] and "remove the package" in b["explanation"]["fix"]


def test_explanation_never_changes_decision():
    f = [fnd("CVE-2026-1111", "p", "exposed")]
    reasons, _ = gate.decide([res("crit", "FAIL")], f, CAT, [])
    assert ids(reasons) == [("check", "crit"), ("cve", "CVE-2026-1111")]


def test_assumptions_always_present_and_explanation_in_table(capsys, wired):
    rc, out, _ = run(capsys, "--docker", "c", "--format", "json")
    assert rc == 0 and len(json.loads(out)["assumptions"]) == 2
    wired["results"] = [res("crit", "FAIL")]
    rc, out, _ = run(capsys, "--docker", "c")
    for w in ("Where:", "Why:", "Exploit:", "Fix:", "assumptions:", "Docker socket"):
        assert w in out


def test_marked_path_not_in_explanation():
    f = {**fnd("CVE-2026-1111", "p", "exposed", reason=f"/opt/{MARKER}/lib.so"), "installed_version": "1"}
    (r,), _ = gate.decide(OK, [f], CAT, [], "c")
    assert MARKER not in json.dumps(r["explanation"])


# --- INV-86 JUnit ------------------------------------------------------------------------

import xml.etree.ElementTree as ET  # noqa: E402


def junit(capsys, *argv):
    rc, out, err = run(capsys, "--docker", "c", "--format", "junit", *argv)
    return rc, (ET.fromstring(out) if out else None), out, err


def test_junit_pass_counts_and_properties(capsys, wired):
    wired["findings"] = [fnd("CVE-2026-1111", "p", "not_exposed", reason="not_executable")]
    rc, root, out, _ = junit(capsys)
    assert rc == 0 and out.startswith("<testsuites")
    suite = root.find("testsuite")
    assert (suite.get("name"), suite.get("tests"), suite.get("failures")) == ("invariant-gate", "2", "0")
    assert [(t.get("classname"), t.get("name")) for t in suite.findall("testcase")] == [("invariant.checks", "crit"), ("invariant.kev", "CVE-2026-1111")]
    assert "p: not_exposed (not_executable)" in suite.findall("testcase")[1].find("system-out").text
    props = {p.get("name"): p.get("value") for p in suite.find("properties")}
    assert props["decision"] == "pass" and props["target"] == "c" and props["image_ref"] == "r" and props["kev_catalog_version"] == "v"
    assert set(props) == {"decision", "target", "image_ref", "invariant_version", "catalog_version", "trivy_version", "kev_catalog_version", "run_id"}


def test_junit_block_failure_has_explanation_and_na_is_skipped(capsys, wired):
    wired["results"] = [res("crit", "FAIL")]
    wired["findings"] = [fnd("CVE-2026-1111", "p", "exposed", reason="listener_maps_package")]
    rc, root, _, _ = junit(capsys)
    assert rc == 1 and root.find("testsuite").get("failures") == "2"
    for t in root.iter("testcase"):
        txt = t.find("failure").text
        assert all(w in txt for w in ("Where:", "Why:", "Exploit:", "Fix:"))
    wired["results"] = [res("crit", "NOT_APPLICABLE")]
    wired["findings"] = []
    rc, root, _, _ = junit(capsys)
    assert rc == 0 and root.find(".//testcase/skipped") is not None and root.find("testsuite").get("skipped") == "1"


def test_junit_missing_critical_check_is_failure(capsys, wired):
    wired["results"] = []
    rc, root, _, _ = junit(capsys)
    assert rc == 1 and root.find(".//testcase/failure").get("type") == "NOT_ASSESSED"


def test_junit_applied_exception_passes_and_says_which(capsys, wired, tmp_path):
    wired["results"] = [res("crit", "FAIL")]
    p = write(tmp_path, f"exceptions:\n  - {{id: crit, justification: j, owner: alice, expires: {ISO(5)}}}\n")
    rc, root, _, _ = junit(capsys, "--exceptions", p)
    t = root.find(".//testcase")
    assert rc == 0 and t.find("failure") is None
    assert f"exception applied: id=crit owner=alice expires={ISO(5)}" in t.find("system-out").text


def test_junit_escapes_and_never_leaks_marker(capsys, wired):
    wired["findings"] = [fnd("CVE-2026-1111", "p<&>\"", "exposed", reason="x<&>")]
    rc, root, out, err = junit(capsys)
    assert rc == 1 and "p<&>" not in out and "p&lt;&amp;&gt;" in out
    assert 'p<&>"' in root.find(".//testcase[@name='CVE-2026-1111']/failure").get("message")
    assert MARKER not in out + err


@pytest.mark.parametrize("argv,code", [(["--ssh", "u@h"], 2), (["--local"], 2)])
def test_junit_error_prints_no_xml(capsys, wired, argv, code):
    rc, out, _ = run(capsys, *argv, "--format", "junit")
    assert rc == code and out == ""


def test_junit_transport_error_prints_no_xml(capsys, wired, monkeypatch):
    def boom(a):
        raise cli.TransportUnreachableError("no container")
    monkeypatch.setattr(cli, "assess", boom)
    rc, out, _ = run(capsys, "--docker", "c", "--format", "junit")
    assert rc == 3 and out == ""


# --- INV-105 readable output ---------------------------------------------------------------

import os  # noqa: E402
from pathlib import Path  # noqa: E402

OUT_NAMES = {"invariant-gate.json", "invariant-gate.junit.xml", "invariant-gate.md", "invariant-gate.jenkins.md"}


def kf(cve, pkg, exposure, reason, kev=True, **kw):
    return {**fnd(cve, pkg, exposure, kev=kev, reason=reason), "installed_version": "1.0", "severity": "HIGH", "cvss_v3_score": 8.1,
            "kev_date_added": "2026-01-02", "kev_known_ransomware_campaign_use": "Unknown", "fixed_version": None, **kw}


def md_run(capsys, tmp_path, *extra):
    rc, out, err = run(capsys, "--docker", "c", "--out-dir", str(Path(str(tmp_path) + "-out")), *extra)
    return rc, out, err, Path(str(tmp_path) + "-out")


def test_out_dir_writes_four_files_overwrites_and_keeps_exit_code(capsys, wired, tmp_path):
    wired["results"] = [res("crit", "FAIL")]
    rc, out, _, d = md_run(capsys, tmp_path)
    assert rc == 1 and {p.name for p in d.iterdir()} == OUT_NAMES  # created the missing dir, no tmp left over
    assert out.startswith("❌ Deploy blocked: 1 problem")  # stdout keeps the table
    assert json.loads((d / "invariant-gate.json").read_text())["decision"] == "block"
    assert ET.fromstring((d / "invariant-gate.junit.xml").read_text()).find("testsuite") is not None
    wired["results"] = [res("crit", "PASS")]
    rc, _, _, d = md_run(capsys, tmp_path)
    assert rc == 0 and (d / "invariant-gate.md").read_text().startswith("✅ Deploy allowed")


def test_markdown_sections_in_order_and_contrast_numbers(capsys, wired, tmp_path):
    wired["results"] = [res("crit", "FAIL")]
    wired["findings"] = [
        kf("CVE-2026-0001", "blocker", "exposed", "listener_maps_package", fixed_version="2.0"),
        kf("CVE-2026-0002", "docs", "not_exposed", "not_executable"),
        kf("CVE-2026-0003", "nolist", "unknown", "not_in_dpkg", kev=False),
        kf("CVE-2026-0004", "scr", "unknown", "interpreted_code", kev=False),
        kf("CVE-2026-0005", "net", "exposed", "listener_maps_package", kev=False),
    ]
    rc, _, _, d = md_run(capsys, tmp_path)
    t = (d / "invariant-gate.md").read_text()
    assert t.startswith("❌ Deploy blocked: 2 problems\n")
    marks = ["Trivy reported", "### 1.", "<details>", "### 2.", "## Visible, not blocking", "## Other findings", "## Assumptions"]
    pos = [t.index(m) for m in marks]
    assert pos == sorted(pos)
    assert "Invariant blocks on 1. Plus 1 configuration issue Trivy doesn't check." in t
    assert "headers or docs only, nothing runs" in t.split("## Visible")[1]
    assert "1 finding in language packages could not be checked; not blocking, none are actively exploited" in t
    assert "1 finding could not be ruled out (scripts); not blocking, none are actively exploited" in t
    assert "2 findings in network-facing code, 1 actively exploited CVE listed above, the rest are not blocking" in t
    assert "Update blocker to 2.0 and rebuild the image." in t and "reachable from the network" in t
    assert "listener_maps_package" not in t and "not_in_dpkg" not in t  # codes become sentences
    j = (d / "invariant-gate.jenkins.md").read_text()
    assert "<" not in j.replace("\\<", "") and "details" not in j and "- Technical detail\n  - " in j
    assert "listener_maps_package" in (d / "invariant-gate.junit.xml").read_text() and "listener_maps_package" in (d / "invariant-gate.json").read_text()


def test_contrast_uses_real_counts_with_thousands_separator():
    out = {"decision": "block", "reasons": [{"type": "check"}] * 3, "total_findings": 9848, "unique_cves": 6403}
    from invariant_assessment import gate_report
    assert gate_report.contrast(out) == ("Trivy reported 9,848 findings (6,403 unique CVEs) → Invariant blocks on 0. "
                                         "Plus 3 configuration issues Trivy doesn't check.")


def test_titles_and_actions_per_state():
    base = {"installed_version": "1", "severity": "H", "cvss_v3_score": 9, "kev_date_added": "d"}
    (a, b), _ = gate.decide(OK, [{**fnd("CVE-2026-1", "p", "exposed"), **base, "fixed_version": "1.5"},
                                 {**fnd("CVE-2026-2", "q", "unknown"), **base, "fixed_version": None}], CAT, [])
    assert "reachable from the network" in a["title"] and "Update p to 1.5 and rebuild" in a["action"]
    assert "exposure can't be ruled out" in b["title"] and "reachable" not in b["title"]
    assert "remove the package or turn off the service" in b["action"] and "owner and an expiry date" in b["action"]
    (c,), _ = gate.decide([res("crit", "NOT_ASSESSED")], [], CAT, [])
    (m,), _ = gate.decide([], [], CAT, [])
    assert c["title"].startswith("Could not verify") and m["title"].startswith("Could not verify") and c["action"] and m["action"]
    for cid in CRITICAL:
        (r,), _ = gate.decide([res(cid, "FAIL")], [], {cid: {"critical": True}}, [])
        assert r["title"].strip() and r["action"].strip() and r["title"] != f"Critical check {cid} failed"


def test_cap_of_20_reasons_then_and_n_more(capsys, wired, tmp_path):
    wired["findings"] = [kf(f"CVE-2026-{i:04d}", f"p{i}", "exposed", "listener_maps_package") for i in range(23)]
    rc, out, _, d = md_run(capsys, tmp_path)
    t = (d / "invariant-gate.md").read_text()
    assert t.startswith("❌ Deploy blocked: 23 problems") and t.count("### ") == 20 and "…and 3 more" in t and "…and 3 more" in out


def test_kev_class_line_says_those_block(capsys, wired, tmp_path):
    wired["findings"] = [kf("CVE-2026-0001", "a", "unknown", "interpreted_code"), kf("CVE-2026-0002", "b", "unknown", "interpreted_code", kev=False)]
    _, _, _, d = md_run(capsys, tmp_path)
    assert "2 findings could not be ruled out (scripts); 1 actively exploited CVE listed above, the rest are not blocking" in (d / "invariant-gate.md").read_text()


def test_table_starts_with_headline_contrast_and_actions_and_has_no_codes(capsys, wired):
    wired["findings"] = [kf("CVE-2026-0001", "a", "exposed", "listener_maps_package")]
    rc, out, _ = run(capsys, "--docker", "c")
    lines = out.splitlines()
    assert lines[0] == "❌ Deploy blocked: 1 problem" and lines[1].startswith("Trivy reported") and "Action:" in lines[4]
    assert "listener_maps_package" not in out and "a process listening on the network loads this library" in out


@pytest.mark.parametrize("argv,code", [(["--ssh", "u@h"], 2), (["--local"], 2)])
def test_error_with_out_dir_writes_blocked_md_only(capsys, wired, tmp_path, argv, code):
    d = Path(str(tmp_path) + "-out")
    rc, out, err = run(capsys, *argv, "--out-dir", str(d))
    assert rc == code and out == ""
    assert {p.name for p in d.iterdir()} == OUT_NAMES
    for n in (d / "invariant-gate.md", d / "invariant-gate.jenkins.md"):
        t = n.read_text()
        assert t.startswith("⛔ Gate could not run (pipeline error): deploy blocked") and "usage error" in t


def test_transport_error_with_out_dir(capsys, wired, tmp_path, monkeypatch):
    def boom(a):
        raise cli.TransportUnreachableError("no container")
    monkeypatch.setattr(cli, "assess", boom)
    rc, out, _, d = md_run(capsys, tmp_path)
    assert rc == 3 and out == ""
    assert "no container" in (d / "invariant-gate.md").read_text()


@pytest.mark.parametrize("sub", ["", "sub/dir"])
def test_out_dir_inside_cache_is_refused(capsys, wired, tmp_path, sub):
    cache = os.environ[vuln.CACHE_ENV]
    rc, out, err = run(capsys, "--docker", "c", "--out-dir", os.path.join(cache, sub))
    assert rc == 2 and out == "" and "cache" in err and os.listdir(cache) == []


def test_write_is_atomic(tmp_path, monkeypatch):
    from invariant_assessment import gate_report
    f = tmp_path / "invariant-gate.md"
    f.write_text("old")
    monkeypatch.setattr(os, "replace", lambda *a: (_ for _ in ()).throw(OSError("boom")))
    with pytest.raises(OSError):
        gate_report.write_atomic(f, "new")
    assert f.read_text() == "old" and [p.name for p in tmp_path.iterdir()] == ["invariant-gate.md"]
    monkeypatch.undo()
    gate_report.write_atomic(f, "new")
    assert f.read_text() == "new" and len(list(tmp_path.iterdir())) == 1


EVIL = "x<script>alert(1)</script>|a](javascript:alert(1))\x1b[31mred\x1b[0m\nINJECT *b* _c_ `d`\x07"


def test_injection_in_package_and_evidence_is_neutralised_in_all_outputs(capsys, wired, tmp_path):
    wired["results"] = [{**res("crit", "FAIL"), "evidence": EVIL}]
    wired["findings"] = [kf("CVE-2026-0001", EVIL, "exposed", "listener_maps_package", installed_version=EVIL)]
    rc, table, _, d = md_run(capsys, tmp_path)
    assert rc == 1
    for name in ("invariant-gate.md", "invariant-gate.jenkins.md"):
        t = (d / name).read_text()
        assert "<script>" not in t and "\x1b" not in t and "\x07" not in t
        assert "\\<script\\>" in t and "\\](javascript:" in t and t.count("](javascript:") == t.count("\\](javascript:")
        assert "\nINJECT" not in t  # the line break did not start a new line
        assert "\\*b\\*" in t and "\\_c\\_" in t and "\\`d\\`" in t and "\\|" in t
    assert "\x1b" not in table and "\x07" not in table and "\nINJECT" not in table
    xml = (d / "invariant-gate.junit.xml").read_text()
    assert "<script>" not in xml and "&lt;script&gt;" in xml
    ET.fromstring(xml)  # still well-formed with control characters in the data


def test_unclassified_context_code_never_reaches_human_files(capsys, wired, tmp_path):
    wired["results"] = [res("crit", "FAIL")]
    wired["findings"] = [kf("CVE-2026-0001", "p", "exposed", f"/opt/{MARKER}/lib.so")]
    rc, out, err, d = md_run(capsys, tmp_path)
    assert rc == 1 and MARKER not in out + err + "".join((d / n).read_text() for n in ("invariant-gate.md", "invariant-gate.jenkins.md"))


def test_error_after_success_in_same_dir_overwrites_all_four(capsys, wired, tmp_path, monkeypatch):
    rc, _, _, d = md_run(capsys, tmp_path)
    assert rc == 0 and "pass" in (d / "invariant-gate.json").read_text()
    monkeypatch.setattr(cli, "assess", lambda a: (_ for _ in ()).throw(RuntimeError("boom")))
    rc, _, _, d = md_run(capsys, tmp_path)
    assert rc == 4
    assert json.loads((d / "invariant-gate.json").read_text()) == {"decision": "error", "exit_code": 4, "error": "unexpected error: RuntimeError"}
    (tc,) = ET.parse(d / "invariant-gate.junit.xml").getroot().iter("testcase")
    assert (tc.get("classname"), tc.get("name")) == ("invariant.gate", "gate") and tc.find("error").get("message") and tc.find("failure") is None
    for n in ("invariant-gate.md", "invariant-gate.jenkins.md"):
        assert (d / n).read_text().startswith("⛔ Gate could not run")
