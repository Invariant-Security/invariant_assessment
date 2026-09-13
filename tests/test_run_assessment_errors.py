"""Unit coverage for POST /assessment/run's collection-failure handling --
monkeypatches collect_facts, no real Docker socket needed. Companion to
test_check_endpoint.py's equivalent case: found live that a container
with no shell at all (loki) made collect_facts() raise a plain
LookupError that neither endpoint used to catch, surfacing as an
unhandled 500 instead of a clean error.
"""

from fastapi.testclient import TestClient

from invariant_assessment import api
from invariant_assessment.api import app

client = TestClient(app)


def test_collection_failure_returns_422_not_500(monkeypatch):
    def raise_collection_error(transport):
        raise LookupError("collection script did not run as expected, got: 'exec: \"sh\": not found'")

    monkeypatch.setattr(api, "collect_facts", raise_collection_error)

    response = client.post("/assessment/run", params={"target": "loki"})

    assert response.status_code == 422
    assert "did not run as expected" in response.json()["detail"]
