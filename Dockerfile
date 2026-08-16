# syntax=docker/dockerfile:1

FROM python:3.11-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# Install uv (used to install dependencies from pyproject.toml)
RUN pip install --no-cache-dir uv

# Install dependencies first for better layer caching
COPY pyproject.toml ./
RUN uv pip install --system --no-cache -r pyproject.toml || true
COPY uv.lock* ./
RUN if [ -f uv.lock ]; then uv sync --frozen --no-dev; fi

# Copy application source
COPY src ./src
COPY ui ./ui

# Fall back to a plain pip install of runtime deps if uv sync above did not
# already populate the environment (keeps this Dockerfile usable even
# without a committed uv.lock).
RUN uv pip install --system --no-cache \
    "fastapi>=0.116,<1" \
    "pydantic>=2.8,<3" \
    "pydantic-ai>=0.7,<1" \
    "uvicorn>=0.30,<1" \
    "python-dotenv>=1.0,<2"

ENV PYTHONPATH=/app/src \
    HOST=0.0.0.0 \
    PORT=8000

EXPOSE 8000

# Container-level health check hitting the app's own /health endpoint.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health')" || exit 1

CMD ["uvicorn", "control_translation.api:app", "--host", "0.0.0.0", "--port", "8000"]
