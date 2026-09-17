"""Unit coverage for GET /assessment/containers -- monkeypatches
list_docker_containers so this runs without a real Docker socket.
"""

from fastapi.testclient import TestClient

from invariant_assessment import api
from invariant_assessment.api import app

client = TestClient(app)


def test_returns_containers_from_list_docker_containers(monkeypatch):
    monkeypatch.setattr(
        api,
        "list_docker_containers",
        lambda: [{"name": "web-1", "image": "nginx:1.27-alpine", "id": "a1b2c3d4e5f6", "is_demo": False}],
    )

    response = client.get("/assessment/containers")

    assert response.status_code == 200
    assert response.json() == [{"name": "web-1", "image": "nginx:1.27-alpine", "id": "a1b2c3d4e5f6", "is_demo": False}]


def test_is_demo_flows_through_for_labeled_containers(monkeypatch):
    monkeypatch.setattr(
        api,
        "list_docker_containers",
        lambda: [{"name": "demo-web-01", "image": "demo-lab/web:1", "id": "f6e5d4c3b2a1", "is_demo": True}],
    )

    response = client.get("/assessment/containers")

    assert response.status_code == 200
    assert response.json()[0]["is_demo"] is True


def test_empty_list_returns_empty_array(monkeypatch):
    monkeypatch.setattr(api, "list_docker_containers", lambda: [])

    response = client.get("/assessment/containers")

    assert response.status_code == 200
    assert response.json() == []
