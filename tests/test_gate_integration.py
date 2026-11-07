"""INV-84 against the running lab pair (read only; skipped when they, Trivy or the cache are missing)."""

import json
import os
import shutil
import subprocess
import sys

import pytest

pytestmark = pytest.mark.integration
CACHE = os.environ.get("INVARIANT_TRIVY_CACHE")


def _running(name):
    r = subprocess.run(["docker", "inspect", "-f", "{{.State.Running}}", name], capture_output=True, text=True)
    return r.stdout.strip() == "true"


if not shutil.which("trivy") or not CACHE or not os.path.isdir(CACHE) or not shutil.which("docker") \
        or not (_running("poc-cd-exposed") and _running("poc-cd-idle")):
    pytest.skip("needs trivy, INVARIANT_TRIVY_CACHE and the running poc-cd-exposed/poc-cd-idle containers", allow_module_level=True)


def _gate(container):
    r = subprocess.run([sys.executable, "-m", "invariant_assessment.cli", "gate", "--docker", container, "--format", "json"],
                       capture_output=True, text=True, timeout=900)
    return r.returncode, json.loads(r.stdout)


def test_exposed_blocks_with_two_reasons_and_idle_passes():
    rc, d = _gate("poc-cd-exposed")
    assert rc == 1 and d["decision"] == "block"
    assert [(r["type"], r["id"]) for r in d["reasons"]] == [("check", "etc_shadow_permissions"), ("cve", "CVE-2026-111497")]
    assert all({"where", "why", "exploit", "fix"} == set(r["explanation"]) for r in d["reasons"]) and len(d["assumptions"]) == 2
    rc, d = _gate("poc-cd-idle")
    assert rc == 0 and d["decision"] == "pass" and d["reasons"] == []
    assert len(d["assumptions"]) == 2


def test_junit_format_real_labs():
    import xml.etree.ElementTree as ET

    for name, rc_want, fails in (("poc-cd-exposed", 1, ["CVE-2026-111497", "etc_shadow_permissions"]), ("poc-cd-idle", 0, [])):
        r = subprocess.run([sys.executable, "-m", "invariant_assessment.cli", "gate", "--docker", name, "--format", "junit"],
                           capture_output=True, text=True, timeout=900)
        suite = ET.fromstring(r.stdout).find("testsuite")
        assert r.returncode == rc_want and int(suite.get("failures")) == len(fails)
        assert sorted(t.get("name") for t in suite.findall("testcase") if t.find("failure") is not None) == fails


def test_out_dir_real_labs(tmp_path):
    """INV-105: one run writes the four files; the Markdown is the readable verdict."""
    import xml.etree.ElementTree as ET

    for name, rc_want, head in (("poc-cd-exposed", 1, "❌ Deploy blocked: 2 problems"), ("poc-cd-idle", 0, "✅ Deploy allowed")):
        d = tmp_path / name
        r = subprocess.run([sys.executable, "-m", "invariant_assessment.cli", "gate", "--docker", name, "--out-dir", str(d)],
                           capture_output=True, text=True, timeout=900)
        assert r.returncode == rc_want and r.stdout.startswith(head)
        assert {p.name for p in d.iterdir()} == {"invariant-gate.json", "invariant-gate.junit.xml", "invariant-gate.md", "invariant-gate.jenkins.md"}
        assert (d / "invariant-gate.md").read_text().startswith(head) and "<" not in (d / "invariant-gate.jenkins.md").read_text()
        assert json.loads((d / "invariant-gate.json").read_text())["decision"] == ("block" if rc_want else "pass")
        ET.parse(d / "invariant-gate.junit.xml")
        md = (d / "invariant-gate.md").read_text()
        if rc_want:
            assert md.count("**Action:**") == 2 and "listener_maps_package" not in md and "Visible, not blocking" in md
