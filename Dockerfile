# syntax=docker/dockerfile:1

FROM python:3.11-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# Install uv and resolve dependencies from the project metadata. Dependency
# failures intentionally fail the image build rather than being ignored.
RUN pip install --no-cache-dir uv

# Install dependencies first for better layer caching
COPY pyproject.toml ./
COPY src ./src
RUN uv pip install --system --no-cache .

# Static assets are served by FastAPI and contain no runtime secrets.
COPY ui ./ui

ENV PYTHONPATH=/app/src \
    HOST=0.0.0.0 \
    PORT=8000

EXPOSE 8000

# Container-level health check hitting the app's own /health endpoint.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import os, urllib.request; urllib.request.urlopen('http://127.0.0.1:' + os.getenv('PORT', '8000') + '/ready')" || exit 1

CMD ["python", "-m", "control_translation"]
