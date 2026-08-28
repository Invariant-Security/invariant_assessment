# syntax=docker/dockerfile:1
FROM python:3.12-slim

WORKDIR /app

# docker CLI, not the daemon -- collect_facts() shells out to
# `docker exec <target> ...`, so this container needs to reach the host's
# Docker socket (mounted at runtime, see docker-compose.yml) the same way
# the monolith's own subprocess.run(["docker", "exec", ...]) already did.
RUN apt-get update \
    && apt-get install -y --no-install-recommends docker.io \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml README.md ./
COPY src/ ./src/
RUN pip install --no-cache-dir .

EXPOSE 8000
CMD ["uvicorn", "invariant_assessment.api:app", "--host", "0.0.0.0", "--port", "8000"]
