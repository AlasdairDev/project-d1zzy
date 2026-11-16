# syntax=docker/dockerfile:1
# Multi-stage: builder (deps into a venv) -> runtime (slim, non-root) -> test (dev deps).
ARG PYTHON_IMAGE=docker.io/library/python:3.12-slim-bookworm

FROM ${PYTHON_IMAGE} AS builder
COPY --from=ghcr.io/astral-sh/uv:0.9 /uv /usr/local/bin/uv
ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy UV_PROJECT_ENVIRONMENT=/opt/venv \
    UV_PYTHON_DOWNLOADS=never
WORKDIR /app
COPY pyproject.toml uv.lock README.md ./
# The project itself is not installed: code runs from /app via PYTHONPATH, so the dev
# bind mount of ./app is what every process (uvicorn, arq, cli) imports.
RUN uv sync --frozen --no-dev --no-install-project

FROM ${PYTHON_IMAGE} AS runtime
RUN groupadd -g 10001 app && useradd -u 10001 -g app -m -s /usr/sbin/nologin app \
    && apt-get update && apt-get install -y --no-install-recommends tini \
    && rm -rf /var/lib/apt/lists/*
ENV PATH=/opt/venv/bin:$PATH PYTHONPATH=/app PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1
WORKDIR /app
COPY --from=builder /opt/venv /opt/venv
COPY app ./app
COPY alembic ./alembic
COPY alembic.ini ./
COPY deploy/docker/entrypoint.sh /entrypoint.sh
RUN chmod 0755 /entrypoint.sh
USER 10001:10001
EXPOSE 8000
ENTRYPOINT ["/usr/bin/tini", "--", "/entrypoint.sh"]
CMD ["web"]

# Test image: dev deps + Node (for the JS<->Python crypto compatibility tests).
FROM runtime AS test
USER root
COPY --from=builder /usr/local/bin/uv /usr/local/bin/uv
COPY pyproject.toml uv.lock README.md ./
RUN UV_PROJECT_ENVIRONMENT=/opt/venv uv sync --frozen --extra dev --no-install-project \
    && apt-get update && apt-get install -y --no-install-recommends nodejs \
    && rm -rf /var/lib/apt/lists/*
COPY tests ./tests
USER 10001:10001
ENTRYPOINT []
CMD ["pytest"]
