# invariant_assessment

Evaluates a target's collected system facts (`docker exec`) against every
implemented CIS control. No Postgres access -- returns raw check
titles/status/evidence; `invariant_api` joins that against real CIS
controls to build a `Finding`.

Extracted from the `Invariant-Security/Invariant` monolith
(`src/invariant/assessment/`) as part of its split into `invariant_*`
services. `evaluate()`/`evidence()` logic for every `Check` is ported
unchanged -- only the wiring around it (no more direct Postgres lookup,
exposed over HTTP instead of called in-process) changed.

## Endpoints

- `GET /healthz`
- `POST /assessment/run?target=<container-name>` -- one `docker exec`
  round trip, then every `CHECKS` entry evaluated against that snapshot.
  Returns `{"document": "...", "results": [{"titles": [...], "status":
  "PASS"|"FAIL", "evidence": "..."}]}`.

## Development

```bash
pip install -e ".[dev]"
pytest tests/ -q                 # unit tests, no Docker needed
pytest tests/ -q -m integration  # needs the 6 real containers, see CI workflow
uvicorn invariant_assessment.api:app --reload
```

## Locked dependencies

`requirements.lock` (hashed) is what the image and CI install; `pyproject.toml` keeps the loose ranges.
Regenerate (add/bump a dep): in `python:3.12.14-slim@<digest>`, `pip install pip-tools && pip-compile --generate-hashes --strip-extras --allow-unsafe -o requirements.lock` with the deps from `pyproject.toml` as input.
Bump the base: `docker buildx imagetools inspect python:3.12.14-slim` (or the new tag) → put the index `Digest:` in the Dockerfile `ARG BASE`, then rebuild and run `pip check`.
