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


MARKER_EXE = "exe-marcado-9d41c7"


def _spawn(container, name):
    """A copy of `sleep` under a unique executable name, running in the container."""
    subprocess.run(["docker", "exec", "-d", container, "sh", "-c", f"cp /bin/sleep /usr/local/bin/{name} && exec /usr/local/bin/{name} 60"], check=True)
    for _ in range(20):
        if subprocess.run(["docker", "exec", container, "sh", "-c", f"readlink /proc/[0-9]*/exe | grep -q /usr/local/bin/{name}"]).returncode == 0:
            return
        subprocess.run(["sleep", "0.2"])
    raise AssertionError("process did not start")


def test_executable_list_never_leaves_the_target(caplog):
    import logging

    from conftest import AUTH_HEADERS
    from fastapi.testclient import TestClient

    from invariant_assessment.api import app

    c = f"{FIXTURE_PREFIX}-debian-baseline"
    _spawn(c, MARKER_EXE)
    env = {**__import__("os").environ, "INVARIANT_DEBUG": "1", "PYTHONLOGLEVEL": "DEBUG"}
    for fmt in ("json", "table"):
        r = _assess(c, fmt, env)
        assert r.returncode == 0, r.stderr
        assert MARKER_EXE not in r.stdout + r.stderr
    caplog.set_level(logging.DEBUG)
    resp = TestClient(app, headers=AUTH_HEADERS).post("/assessment/run", params={"target": c})
    assert resp.status_code == 200 and MARKER_EXE not in resp.text
    assert MARKER_EXE not in caplog.text


def test_running_sudo_executable_is_seen():
    c = f"{FIXTURE_PREFIX}-ubuntu-baseline"
    _spawn(c, "sudo")
    d = json.loads(_assess(c).stdout)
    meta, _ = cli.load_catalog()
    sudo_checks = [x for x in d["results"] if meta[x["check_id"]]["requires"] == "sudo" and not meta[x["check_id"]]["host_only"]]
    assert sudo_checks and all(x["effective_status"] == x["status"] for x in sudo_checks)
