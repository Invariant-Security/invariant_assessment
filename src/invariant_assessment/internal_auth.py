"""Autenticação de quem chama este serviço interno.

Rede Docker não é autenticação: mesmo sem porta publicada, este serviço só
atende quem apresenta o token próprio dele (`INVARIANT_INTERNAL_ASSESSMENT_TOKEN`), em
`Authorization: Bearer <token>`. Cada serviço interno tem o seu token --
vazar um não autentica nos outros. Só `/healthz` fica livre (healthcheck do
compose; não expõe nada). Comparação em tempo constante; o token nunca é
logado nem devolvido.
"""

import hmac
import os
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

TOKEN_ENV = "INVARIANT_INTERNAL_ASSESSMENT_TOKEN"
PUBLIC_PATHS = frozenset({"/healthz"})


def _expected_token() -> str:
    return os.environ.get(TOKEN_ENV, "")


def require_configured_token() -> None:
    """Falha o startup se o token não estiver definido (fail-closed e visível:
    o container não sobe em vez de subir aberto ou recusando tudo em silêncio)."""
    if not _expected_token():
        raise RuntimeError(f"{TOKEN_ENV} não definido -- serviço interno não sobe sem token")


def install(app: FastAPI) -> None:
    previous_lifespan = app.router.lifespan_context

    @asynccontextmanager
    async def _lifespan(a):
        require_configured_token()
        async with previous_lifespan(a) as state:
            yield state

    app.router.lifespan_context = _lifespan

    @app.middleware("http")
    async def _require_internal_token(request: Request, call_next):
        if request.url.path in PUBLIC_PATHS:
            return await call_next(request)
        expected = _expected_token()
        scheme, _, given = request.headers.get("authorization", "").partition(" ")
        if not expected or scheme.lower() != "bearer" or not hmac.compare_digest(given.encode(), expected.encode()):
            return JSONResponse({"detail": "unauthorized"}, status_code=401)
        return await call_next(request)
