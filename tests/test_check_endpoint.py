"""Unit coverage for POST /assessment/check -- monkeypatches collect_facts
so this runs without a real Docker socket, unlike test_transport.py's
integration tests. Mirrors the exact os_id/os_version_id -> testable gate
_evaluate_all() uses for the real assessment, without running any checks.
"""

from fastapi.testclient import TestClient

from invariant_assessment import api
from invariant_assessment.api import app
from invariant_assessment.facts import SystemFacts

client = TestClient(app)


def _facts(os_id=None, os_version_id=None) -> SystemFacts:
    return SystemFacts(os_id=os_id, os_version_id=os_version_id, sshd_config={}, file_stats={})


def test_supported_os_is_testable(monkeypatch):
    monkeypatch.setattr(api, "collect_facts", lambda transport: _facts("debian", "12"))

    response = client.post("/assessment/check", params={"target": "tamois"})

    assert response.status_code == 200
    body = response.json()
    assert body == {
        "testable": True,
        "os_id": "debian",
        "os_version_id": "12",
        "family": "debian_ubuntu",
        "reason_code": None,
        "reason": None,
    }


def test_unsupported_os_returns_clean_reason_not_raw_exception_text(monkeypatch):
    monkeypatch.setattr(api, "collect_facts", lambda transport: _facts("alpine", "3.23"))

    response = client.post("/assessment/check", params={"target": "estudeoab-backend-1"})

    assert response.status_code == 200
    body = response.json()
    assert body["testable"] is False
    assert body["reason_code"] == "unsupported_os"
    assert body["reason"] == "alpine 3.23 is not supported yet."
    assert "LookupError" not in body["reason"]  # never the raw exception repr


def test_collection_failure_is_not_an_unhandled_500(monkeypatch):
    # Found live against loki (a distroless-style image with no `sh` at
    # all): "docker exec ... sh -c ..." fails at the OCI runtime level,
    # and the transport surfaces that as a plain LookupError from
    # facts._parse_collect_output(), not one of the OS-detection cases.
    def raise_collection_error(transport):
        raise LookupError("collection script did not run as expected, got: 'exec: \"sh\": not found'")

    monkeypatch.setattr(api, "collect_facts", raise_collection_error)

    response = client.post("/assessment/check", params={"target": "loki"})

    assert response.status_code == 200
    body = response.json()
    assert body["testable"] is False
    assert body["reason_code"] == "collection_failed"
    assert "LookupError" not in body["reason"]


def test_os_not_detected(monkeypatch):
    monkeypatch.setattr(api, "collect_facts", lambda transport: _facts(None, None))

    response = client.post("/assessment/check", params={"target": "mystery"})

    assert response.status_code == 200
    body = response.json()
    assert body["testable"] is False
    assert body["reason_code"] == "os_not_detected"
    assert body["os_id"] is None


def test_response_is_never_cached(monkeypatch):
    monkeypatch.setattr(api, "collect_facts", lambda transport: _facts("debian", "12"))

    response = client.post("/assessment/check", params={"target": "tamois"})

    assert response.headers["cache-control"] == "no-store"
