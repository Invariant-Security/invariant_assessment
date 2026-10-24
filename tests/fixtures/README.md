# Fixtures de teste

`docker compose -f tests/fixtures/docker-compose.yml up -d --build --wait`

Variáveis (todas opcionais; os defaults são os nomes/portas históricos):

| Variável | Default | Efeito |
|---|---|---|
| `INVARIANT_FIXTURE_PREFIX` | `invariant` | prefixo dos `container_name` (`<prefixo>-debian-baseline`, ..., `<prefixo>-assessment-test-ssh-target[-nonroot]`) |
| `INVARIANT_SSH_TARGET_PORT` | `22022` | porta (só loopback) do ssh-target |
| `INVARIANT_SSH_TARGET_NONROOT_PORT` | `22023` | porta (só loopback) do ssh-target-nonroot |

Os testes leem as mesmas variáveis (`tests/conftest.py`). Para isolar uma
rodada (CI, sessão paralela) use prefixo + `COMPOSE_PROJECT_NAME` próprios e
portas livres; derrube com `down -v`.
