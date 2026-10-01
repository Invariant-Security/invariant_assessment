"""Autenticação interna por HTTP real (uvicorn numa porta local, sem
TestClient): a rede Docker não é autenticação, então o serviço sozinho tem
que recusar quem não apresenta o token dele."""

import json
import os
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request

import pytest
import uvicorn

from invariant_assessment.api import app
from invariant_assessment.internal_auth import TOKEN_ENV

TOKEN = "token-de-teste-" + "a" * 48
OPERATIONAL = ("GET", "/assessment/containers", None)


@pytest.fixture
def live_url(monkeypatch):
    monkeypatch.setenv(TOKEN_ENV, TOKEN)
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=0, log_level="warning"))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    deadline = time.time() + 15
    while not server.started:
        assert time.time() < deadline, "servidor não subiu"
        time.sleep(0.02)
    port = server.servers[0].sockets[0].getsockname()[1]
    yield f"http://127.0.0.1:{port}"
    server.should_exit = True
    thread.join(timeout=10)


def _call(url, method, path, body=None, authorization=None):
    data = None if body is None else json.dumps(body).encode()
    req = urllib.request.Request(url + path, data=data, method=method)
    if data is not None:
        req.add_header("Content-Type", "application/json")
    if authorization is not None:
        req.add_header("Authorization", authorization)
    try:
        with urllib.request.urlopen(req, timeout=120) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


@pytest.mark.parametrize(
    "authorization",
    [None, "Bearer errado", f"Basic {TOKEN}", f"Bearer {TOKEN}x", "Bearer ", TOKEN],
    ids=["sem-token", "token-errado", "esquema-errado", "token-com-sufixo", "vazio", "sem-esquema"],
)
def test_operational_route_refuses_without_the_right_token(live_url, authorization):
    method, path, body = OPERATIONAL
    status, payload = _call(live_url, method, path, body, authorization)
    assert status == 401
    assert json.loads(payload) == {"detail": "unauthorized"}
    assert TOKEN.encode() not in payload


def test_operational_route_works_with_the_right_token(live_url):
    method, path, body = OPERATIONAL
    status, _ = _call(live_url, method, path, body, f"Bearer {TOKEN}")
    assert status == 200


def test_healthz_is_public_and_openapi_is_not(live_url):
    assert _call(live_url, "GET", "/healthz")[0] == 200
    assert _call(live_url, "GET", "/openapi.json")[0] == 401
    assert _call(live_url, "GET", "/openapi.json", authorization=f"Bearer {TOKEN}")[0] == 200


def test_service_does_not_start_without_token():
    env = {k: v for k, v in os.environ.items() if k != TOKEN_ENV}
    proc = subprocess.run(
        [sys.executable, "-m", "uvicorn", "invariant_assessment.api:app", "--host", "127.0.0.1", "--port", "0"],
        env=env, capture_output=True, text=True, timeout=60,
    )
    assert proc.returncode != 0
    assert TOKEN_ENV in proc.stderr
