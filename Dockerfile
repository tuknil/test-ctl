ARG BASE_IMAGE=artifact.it.att.com/astra-secure-container-catalog/python:3.12
FROM ${BASE_IMAGE} AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# Run the service and its durable store without root privileges.
RUN addgroup --system app && adduser --system --ingroup app app

# Install dependencies first for better layer caching
COPY pyproject.toml ./
COPY src ./src
# The corporate pip configuration is supplied as a build secret and exists
# only for this layer. It is never copied into the image or build context.
RUN --mount=type=secret,id=pip_conf,target=/etc/pip.conf,required=true \
    pip install --no-cache-dir .

# Static assets are served by FastAPI and contain no runtime secrets.
COPY ui ./ui

RUN mkdir -p /app/data && chown -R app:app /app

ENV PYTHONPATH=/app/src \
    HOST=0.0.0.0 \
    PORT=8000 \
    PERSISTENCE_BACKEND=sqlite \
    DATABASE_PATH=/app/data/control_translation.db \
    SERVICE_REPLICA_COUNT=1

USER app

EXPOSE 8000

# Container-level health check hitting the app's own /health endpoint.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import os, urllib.request; urllib.request.urlopen('http://127.0.0.1:' + os.getenv('PORT', '8000') + '/ready')" || exit 1

# The secure base image may define a Python entrypoint. Clear it so the
# service command below is not interpreted as a Python script path.
ENTRYPOINT []

CMD ["python", "-m", "control_translation"]
