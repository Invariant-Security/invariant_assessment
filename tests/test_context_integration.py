"""INV-83 against the running lab pair (read only; skipped when they or Trivy are missing)."""

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


def _states(container):
    r = subprocess.run([sys.executable, "-m", "invariant_assessment.context", "--docker", container],
                       capture_output=True, text=True, timeout=900)
    assert r.returncode == 0, r.stderr
    out = {}
    for f in json.loads(r.stdout)["findings"]:
        out.setdefault((f["cve"], f["package"]), (f["exposure"], f["context_reason"]))
    return out


def test_brotli_exposed_only_where_the_listener_loads_it():
    exposed, idle = _states("poc-cd-exposed"), _states("poc-cd-idle")
    for pkg in ("libbrotli1", "libbrotli-dev"):
        k = ("CVE-2026-111497", pkg)
        assert exposed[k] == ("exposed", "listener_maps_package")
        assert idle[k][0] == "not_exposed"
    assert {v for k, v in exposed.items() if k[1] == "linux-libc-dev"} == {("not_exposed", "not_executable")}
