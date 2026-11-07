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
    assert rc == 1 and out.startswith("DECISION: BLOCK") and "CVE-2026-1111" in out  # KEV listed though not blocking


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
    for fmt in ("json", "table"):
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
