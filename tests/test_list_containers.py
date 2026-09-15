"""Unit coverage for transport.list_docker_containers() -- monkeypatches
subprocess.run so this runs without a real Docker socket, unlike
test_transport.py's integration tests against real containers.
"""

import subprocess
from unittest.mock import MagicMock

from invariant_assessment.transport import list_docker_containers


def _fake_run(stdout):
    def run(*args, **kwargs):
        return MagicMock(stdout=stdout, stderr="")

    return run


def test_parses_name_and_image_pairs(monkeypatch):
    monkeypatch.setattr(
        subprocess,
        "run",
        _fake_run("web-1|nginx:1.27-alpine\napi-1|myorg/api:latest\n"),
    )

    result = list_docker_containers()

    assert result == [
        {"name": "web-1", "image": "nginx:1.27-alpine"},
        {"name": "api-1", "image": "myorg/api:latest"},
    ]


def test_empty_output_returns_empty_list(monkeypatch):
    monkeypatch.setattr(subprocess, "run", _fake_run(""))

    assert list_docker_containers() == []


def test_ignores_blank_lines(monkeypatch):
    monkeypatch.setattr(subprocess, "run", _fake_run("web-1|nginx:1.27-alpine\n\n"))

    assert list_docker_containers() == [{"name": "web-1", "image": "nginx:1.27-alpine"}]
