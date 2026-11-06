"""`invariant assess --docker` against the real fixture containers."""

import hashlib
import json
import subprocess
import sys

import pytest
from conftest import FIXTURE_PREFIX

from invariant_assessment import cli

pytestmark = pytest.mark.integration


def _assess(container, fmt="json", env=None):
    return subprocess.run([sys.executable, "-m", "invariant_assessment.cli", "assess", "--docker", container, "--format", fmt],
                          capture_output=True, text=True, timeout=120, env=env)


@pytest.mark.parametrize("name", ["debian-baseline", "ubuntu-baseline", "debian-ssh-bad"])
def test_docker_json(name):
    r = _assess(f"{FIXTURE_PREFIX}-{name}")
    assert r.returncode == 0, r.stderr
    d = json.loads(r.stdout)
    assert d["transport"] == "docker" and d["target"] == f"{FIXTURE_PREFIX}-{name}"
    assert d["catalog_version"] == hashlib.sha256(cli.CATALOG_PATH.read_bytes()).hexdigest()
    assert d["image_digest"] and d["image_digest_kind"] in ("repo_digest", "image_id")
    assert len(d["results"]) == 199
    meta, _ = cli.load_catalog()
    for x in d["results"]:
        assert x["status"] in ("PASS", "FAIL", "NOT_ASSESSED")
        want = "NOT_APPLICABLE" if meta[x["check_id"]]["host_only"] else x["effective_status"]
        assert x["effective_status"] == want


def test_docker_table_and_missing_container():
    r = _assess(f"{FIXTURE_PREFIX}-debian-baseline", "table")
    assert r.returncode == 0 and "summary:" in r.stdout
    assert _assess(f"{FIXTURE_PREFIX}-nao-existe").returncode == 3
