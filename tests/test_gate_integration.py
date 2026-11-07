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
