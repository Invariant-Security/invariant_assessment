"""O serviço exige o token interno em toda rota operacional (ver
internal_auth.py). Os testes de rota usam este token; o teste de
autenticação em si (test_internal_auth.py) define o próprio."""

import os

from invariant_assessment.internal_auth import TOKEN_ENV

TEST_TOKEN = "token-dos-testes-de-rota-" + "b" * 40
os.environ.setdefault(TOKEN_ENV, TEST_TOKEN)
AUTH_HEADERS = {"Authorization": f"Bearer {os.environ[TOKEN_ENV]}"}

# Fixtures (tests/fixtures/README.md): mesmos defaults do compose.
FIXTURE_PREFIX = os.environ.get("INVARIANT_FIXTURE_PREFIX", "invariant")
SSH_TARGET_PORT = int(os.environ.get("INVARIANT_SSH_TARGET_PORT", "22022"))
SSH_TARGET_NONROOT_PORT = int(os.environ.get("INVARIANT_SSH_TARGET_NONROOT_PORT", "22023"))
