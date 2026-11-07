"""INV-81 with the real Trivy and a local DB (skipped when either is missing: CI has no DB)."""

import json
import os
import shutil
import subprocess
import sys

import pytest

pytestmark = pytest.mark.integration
CACHE = os.environ.get("INVARIANT_TRIVY_CACHE")
if not shutil.which("trivy") or not CACHE or not os.path.isdir(CACHE):
    pytest.skip("needs trivy in PATH and INVARIANT_TRIVY_CACHE with a downloaded DB", allow_module_level=True)


def test_real_scan_of_a_local_image():
    image = os.environ.get("INVARIANT_TRIVY_TEST_IMAGE", "node:20")
    r = subprocess.run([sys.executable, "-m", "invariant_assessment.vuln", image], capture_output=True, text=True, timeout=900)
    assert r.returncode == 0, r.stderr
    d = json.loads(r.stdout)
    assert d["total_findings"] == len(d["findings"]) >= d["unique_cves"] > 0
    assert d["trivy_version"]
