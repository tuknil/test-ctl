# Lean capability API: read the proven ModSecurity rule from the Databricks
# rows the request names, compile it into an Akamai custom WAF rule, and
# persist the result in Databricks. The asynchronous lifecycle queue is a
# Postgres database -- Azure Database for PostgreSQL in the deployed
# environment -- so the container keeps no state of its own.
#
# Built from the repository root:
#   docker build -f go-api/Dockerfile -t control-translation-go:<tag> .
# Build the Go API binary.
FROM artifact.it.att.com/astra-secure-container-catalog/go:1.26.5 AS build
ENV GONOSUMDB=off
ENV GOPRIVATE=it.att.com
WORKDIR /src
COPY go-api/go.mod go-api/go.sum ./
RUN go mod download

COPY go-api/ ./
# No cgo: every dependency is pure Go, so the binary is static.
ENV CGO_ENABLED=0
RUN go build -trimpath -ldflags="-s -w" -o /out/control-translation-api ./cmd/api

FROM  artifact.it.att.com/docker-hub/debian:bookworm-slim
ENV GONOSUMDB=off
ENV GOPRIVATE=it.att.com
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --shell /bin/false app
WORKDIR /app
COPY --from=build /out/control-translation-api /app/control-translation-api

ENV HOST=0.0.0.0 \
    PORT=8000 \
    DATABASE_PORT=5432 \
    DATABASE_AUTH_MODE=entra \
    DATABASE_SSL_MODE=verify-full \
    DATABASE_MIGRATION_MODE=external \
    SERVICE_REPLICA_COUNT=1

# No volume: the queue is Postgres and the results are in Databricks, so the
# container holds nothing that has to survive a restart. Replicas may be scaled
# freely -- runs are claimed with FOR UPDATE SKIP LOCKED, so two replicas
# cannot take the same one.
#
# ca-certificates above is what makes DATABASE_SSL_MODE=verify-full work: the
# Azure server certificate is verified against this trust store.
EXPOSE 8000

# The binary answers /ready itself, so the platform probe is the health check.
# distroless carries no shell, so there is no in-image HEALTHCHECK command.
ENTRYPOINT ["/app/control-translation-api"]
