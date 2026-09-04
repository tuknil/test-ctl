# Lean capability API: read the proven ModSecurity rule from the Databricks
# rows the request names, compile it into an Akamai custom WAF rule, and
# persist the result in Databricks. The asynchronous lifecycle queue is the
# one piece of local state.
#
# Built from the repository root:
#   docker build -f go-api/Dockerfile -t control-translation-go:<tag> .
ARG BUILD_IMAGE=golang:1.25-alpine
ARG BASE_IMAGE=gcr.io/distroless/static-debian12:nonroot

FROM ${BUILD_IMAGE} AS build
WORKDIR /src

COPY go-api/go.mod go-api/go.sum ./
RUN go mod download

COPY go-api/ ./
# modernc.org/sqlite is pure Go, so the binary is static and the runtime image
# needs no libc.
ENV CGO_ENABLED=0
RUN go build -trimpath -ldflags="-s -w" -o /out/control-translation-api ./cmd/api
# distroless has no shell, so the lifecycle directory has to be created here
# and copied in with the right ownership. A volume mounted at /app/data
# inherits it, so the nonroot user can write the queue.
RUN mkdir -p /out/data

FROM ${BASE_IMAGE}
WORKDIR /app
COPY --from=build /out/control-translation-api /app/control-translation-api
COPY --from=build --chown=nonroot:nonroot /out/data /app/data

ENV HOST=0.0.0.0 \
    PORT=8000 \
    DATABASE_PATH=/app/data/control_translation.db \
    SERVICE_REPLICA_COUNT=1

# Mount /app/data on durable storage: losing it forgets in-flight runs, though
# any result already written to Databricks survives. Run exactly one replica
# while the queue is a local SQLite file.
USER nonroot:nonroot
EXPOSE 8000

# The binary answers /ready itself, so the platform probe is the health check.
# distroless carries no shell, so there is no in-image HEALTHCHECK command.
ENTRYPOINT ["/app/control-translation-api"]
