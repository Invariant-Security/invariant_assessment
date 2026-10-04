# syntax=docker/dockerfile:1
# python:3.12.14-slim fixado por digest do índice -- atualizar
# conscientemente (README, "Locked dependencies").
ARG BASE=python:3.12.14-slim@sha256:f77ac9e44ae96ef2c90b8053ea08c31f8be030f824196b0ae4db6d462c84e51f
FROM ${BASE}

WORKDIR /app

# docker CLI, not the daemon -- collect_facts() shells out to
# `docker exec <target> ...`, so this container needs to reach the host's
# Docker socket (mounted at runtime, see docker-compose.yml) the same way
# the monolith's own subprocess.run(["docker", "exec", ...]) already did.
#
# `docker.io` (the package, confusingly) pulls in the whole daemon
# (containerd/runc/dbus/...) and, on Debian 13/trixie, doesn't even ship
# /usr/bin/docker itself -- that binary moved to a separate `docker-cli`
# package, which is only a Recommends of docker.io, so
# --no-install-recommends silently skipped it (confirmed: this container
# had docker.io "installed" per dpkg but no docker binary in $PATH at all,
# collect_facts() failing with FileNotFoundError on every real request).
# `docker-cli` alone is the client only -- exactly what's needed here.
RUN apt-get update \
    && apt-get install -y --no-install-recommends docker-cli \
    && rm -rf /var/lib/apt/lists/*

# Dependências antes do código: mudar README/src não reinstala nada.
COPY requirements.lock ./
RUN pip install --no-cache-dir --require-hashes --no-deps -r requirements.lock

COPY pyproject.toml README.md ./
COPY src/ ./src/
RUN pip install --no-cache-dir --no-deps . && pip check

EXPOSE 8000
CMD ["uvicorn", "invariant_assessment.api:app", "--host", "0.0.0.0", "--port", "8000"]
