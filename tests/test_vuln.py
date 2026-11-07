"""INV-81: Trivy report normalization, DB age and the exit-4 cases (no real Trivy)."""

import json
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from invariant_assessment import vuln

SAMPLE = json.loads((Path(__file__).parent / "fixtures" / "trivy_node20_sample.json").read_text())
NOW = datetime(2026, 11, 6, 12, 0, tzinfo=timezone.utc)


def test_normalize_dedup_and_fields():
    f = vuln.normalize(SAMPLE)
    assert len(f) == 4  # 5 entries, one repeated (cve, package)
    assert f[0] == {"cve": "CVE-2026-5773", "package": "curl", "installed_version": "7.88-10+deb12u14",
                    "fixed_version": "7.88-10+deb12u15", "severity": "HIGH", "cvss_v3_score": 7.5}
    assert f[1]["cvss_v3_score"] == 6.6  # no NVD entry: vendor score
    assert f[2]["fixed_version"] is None and f[2]["cvss_v3_score"] is None
    assert vuln.normalize({}) == [] and vuln.normalize({"Results": [{"Vulnerabilities": None}]}) == []


def test_cvss_nvd_first_then_vendor():
    assert vuln._cvss_v3({"redhat": {"V3Score": 5.0}, "nvd": {"V3Score": 9.8}}) == 9.8
    assert vuln._cvss_v3({"nvd": {"V2Score": 4.3}, "redhat": {"V3Score": 5.0}}) == 5.0
    assert vuln._cvss_v3({"nvd": {"V2Score": 4.3}}) is None and vuln._cvss_v3(None) is None


def _stub(monkeypatch, version_json=None, image_json=None, image_rc=0, version_rc=0, image_err=""):
    def fake(argv, timeout):
        if argv[:2] == ["trivy", "version"]:
            return subprocess.CompletedProcess(argv, version_rc, version_json if isinstance(version_json, str) else json.dumps(version_json), "")
        if argv[:2] == ["trivy", "image"]:
            return subprocess.CompletedProcess(argv, image_rc, image_json if isinstance(image_json, str) else json.dumps(image_json), image_err)
        return subprocess.CompletedProcess(argv, 1, "", "")  # docker: not a local image

    monkeypatch.setattr(vuln, "_run", fake)


def version(days_old, java_days_old=1):
    ts = lambda d: (NOW - timedelta(days=d)).strftime("%Y-%m-%dT%H:%M:%S.123456789Z")
    return {"Version": "0.76", "VulnerabilityDB": {"Version": 2, "UpdatedAt": ts(days_old)}, "JavaDB": {"Version": 1, "UpdatedAt": ts(java_days_old)}}


def test_scan_counts_and_extras(monkeypatch):
    _stub(monkeypatch, version(2), SAMPLE)
    out = vuln.scan("img", None, "/c", NOW)
    assert (out["total_findings"], out["unique_cves"]) == (4, len({f["cve"] for f in out["findings"]}))
    assert out["trivy_version"] == "0.76" and out["db_version"] == 2 and out["db_age_warning"] is None
    assert out["image_ref"] == {"ref": "img", "kind": "name"}


@pytest.mark.parametrize("days,warns", [(2, False), (4, True)])
def test_db_age_warning(monkeypatch, capsys, days, warns):
    _stub(monkeypatch, version(days), SAMPLE)
    assert (vuln.scan("img", None, "/c", NOW)["db_age_warning"] is not None) is warns
    monkeypatch.setenv("INVARIANT_TRIVY_CACHE", "/c")
    monkeypatch.setattr(vuln, "scan", lambda *a: {"db_age_warning": "old" if warns else None})
    assert vuln.main(["img"]) == 0
    assert ("warning" in capsys.readouterr().err) is warns


def test_db_age_limits_configurable(monkeypatch):
    _stub(monkeypatch, version(2), SAMPLE)
    monkeypatch.setenv("INVARIANT_TRIVY_DB_WARN_DAYS", "1")
    assert vuln.scan("img", None, "/c", NOW)["db_age_warning"]
    monkeypatch.setenv("INVARIANT_TRIVY_DB_MAX_DAYS", "1.5")
    with pytest.raises(vuln.VulnError):
        vuln.scan("img", None, "/c", NOW)


@pytest.mark.parametrize("kwargs", [
    {"version_json": version(8), "image_json": SAMPLE},  # 8 days
    {"version_json": version(1, 8), "image_json": SAMPLE},  # Java DB 8 days
    {"version_json": {"Version": "0.76"}, "image_json": SAMPLE},  # no DB at all
    {"version_json": "not json", "image_json": SAMPLE},
    {"version_json": version(1), "image_json": "not json"},
    {"version_json": version(1), "image_json": "[]"},
    {"version_json": version(1), "image_json": SAMPLE, "image_rc": 1},
    {"version_json": version(1), "image_json": SAMPLE, "version_rc": 1},
])
def test_exit_4_cases(monkeypatch, capsys, kwargs):
    _stub(monkeypatch, **kwargs)
    monkeypatch.setattr(vuln, "datetime", type("D", (datetime,), {"now": classmethod(lambda cls, tz=None: NOW)}))
    monkeypatch.setenv("INVARIANT_TRIVY_CACHE", "/c")
    monkeypatch.delenv("INVARIANT_DEBUG", raising=False)
    rc = vuln.main(["img"])
    cap = capsys.readouterr()
    assert rc == 4 and cap.out == "" and "Traceback" not in cap.err


def test_no_java_db_is_fine_and_has_no_java_age_check(monkeypatch):
    v = version(2)
    del v["JavaDB"]
    _stub(monkeypatch, v, SAMPLE)
    out = vuln.scan("img", None, "/c", NOW)
    assert out["total_findings"] == 4 and out["db_age_warning"] is None


def test_java_db_age_has_no_warning_only_limit(monkeypatch):
    _stub(monkeypatch, version(1, 5), SAMPLE)  # Java DB 5 days: over warn, under max
    assert vuln.scan("img", None, "/c", NOW)["db_age_warning"] is None


def test_image_with_jars_and_no_java_db_is_4_short(monkeypatch, capsys):
    err = "FATAL\tFatal error\tUnable to initialize the Java DB: '--skip-java-db-update' cannot be specified on the first run\n"
    v = version(1)
    del v["JavaDB"]
    _stub(monkeypatch, v, "", image_rc=1, image_err=err)
    monkeypatch.setattr(vuln, "datetime", type("D", (datetime,), {"now": classmethod(lambda cls, tz=None: NOW)}))
    monkeypatch.setenv("INVARIANT_TRIVY_CACHE", "/c")
    monkeypatch.delenv("INVARIANT_DEBUG", raising=False)
    assert vuln.main(["img"]) == 4
    cap = capsys.readouterr()
    assert cap.out == "" and "Java DB" in cap.err and "Traceback" not in cap.err and "FATAL" not in cap.err


def test_trivy_missing_is_4_and_debug_traceback(monkeypatch, capsys):
    monkeypatch.setenv("PATH", "/nonexistent")
    monkeypatch.setenv("INVARIANT_TRIVY_CACHE", "/c")
    assert vuln.main(["img"]) == 4 and "not found" in capsys.readouterr().err
    monkeypatch.setenv("INVARIANT_DEBUG", "1")
    vuln.main(["img"])
    assert "Traceback" in capsys.readouterr().err


def test_usage_errors_are_2(monkeypatch, capsys):
    monkeypatch.delenv("INVARIANT_TRIVY_CACHE", raising=False)
    assert vuln.main(["img"]) == 2  # no cache dir
    assert vuln.main([]) == 2
    assert vuln.main(["img", "--docker", "c", "--cache-dir", "/c"]) == 2


def test_vuln_is_not_a_public_entry_point():
    assert "vuln" not in (Path(__file__).parent.parent / "pyproject.toml").read_text().split("[project.scripts]")[1].split("[")[0]
