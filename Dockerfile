# syntax=docker/dockerfile:1
FROM node:22-alpine AS frontend-build
WORKDIR /app/frontend
COPY frontend/package.json frontend/package-lock.json ./
RUN --mount=type=cache,target=/root/.npm npm ci
COPY frontend/ ./
RUN npm run build

FROM python:3.12-slim-bookworm AS backend-build
COPY --from=ghcr.io/astral-sh/uv:0.11.22 /uv /usr/local/bin/uv
ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy UV_PYTHON_DOWNLOADS=never
WORKDIR /app/backend
COPY backend/pyproject.toml backend/uv.lock ./
RUN --mount=type=cache,target=/root/.cache/uv uv sync --frozen --no-dev --no-install-project
COPY backend/ ./
RUN --mount=type=cache,target=/root/.cache/uv uv sync --frozen --no-dev

FROM python:3.12-slim-bookworm AS application
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PATH="/app/backend/.venv/bin:$PATH" \
    AUDIT_DATA_DIR=/app/data
RUN groupadd --gid 10001 audit \
    && useradd --uid 10001 --gid audit --no-create-home audit \
    && mkdir -p /app/data \
    && chown audit:audit /app/data
COPY --from=backend-build /app/backend /app/backend
COPY --from=frontend-build /app/frontend/dist /app/frontend/dist
# Scenario tooling travels with the image: register_scenarios.py talks to this very
# instance and score_dataset.py resolves its default truth path relative to the repo
# root.  Both stay read-only at runtime; score_dataset.py takes --out for writable dirs.
COPY scripts/ /app/scripts/
COPY datasets/ /app/datasets/
WORKDIR /app/backend
USER audit
EXPOSE 8899
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8899/api/config', timeout=4)" || exit 1
CMD ["uvicorn", "audit.app:app", "--host", "0.0.0.0", "--port", "8899", "--workers", "1"]
