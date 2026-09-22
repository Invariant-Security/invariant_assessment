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


def test_parses_name_image_id_and_demo_label_quadruples(monkeypatch):
    monkeypatch.setattr(
        subprocess,
        "run",
        _fake_run(
            "web-1|nginx:1.27-alpine|a1b2c3d4e5f6|\n"
            "demo-web-01|demo-lab/web:1|f6e5d4c3b2a1|true\n"
        ),
    )

    result = list_docker_containers()

    assert result == [
        {"name": "web-1", "image": "nginx:1.27-alpine", "id": "a1b2c3d4e5f6", "is_demo": False},
        {"name": "demo-web-01", "image": "demo-lab/web:1", "id": "f6e5d4c3b2a1", "is_demo": True},
    ]


def test_empty_output_returns_empty_list(monkeypatch):
    monkeypatch.setattr(subprocess, "run", _fake_run(""))

    assert list_docker_containers() == []


def test_ignores_blank_lines(monkeypatch):
    monkeypatch.setattr(subprocess, "run", _fake_run("web-1|nginx:1.27-alpine|a1b2c3d4e5f6|\n\n"))

    assert list_docker_containers() == [
        {"name": "web-1", "image": "nginx:1.27-alpine", "id": "a1b2c3d4e5f6", "is_demo": False}
    ]


def test_uses_no_trunc_flag(monkeypatch):
    captured = {}

    def run(args, **kwargs):
        captured["args"] = args
        return MagicMock(stdout="", stderr="")

    monkeypatch.setattr(subprocess, "run", run)

    list_docker_containers()

    assert "--no-trunc" in captured["args"]


def test_format_string_requests_the_demo_label(monkeypatch):
    captured = {}

    def run(args, **kwargs):
        captured["args"] = args
        return MagicMock(stdout="", stderr="")

    monkeypatch.setattr(subprocess, "run", run)

    list_docker_containers()

    format_arg = captured["args"][captured["args"].index("--format") + 1]
    assert 'invariant.public-demo' in format_arg
