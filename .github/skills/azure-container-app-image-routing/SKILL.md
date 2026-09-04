---
name: azure-container-app-image-routing
description: "Use when building, pushing, or deploying JANUS images to Azure Container Apps. Ensures images are always built for linux/amd64 (Apple Silicon defaults to arm64 and causes ImagePullBackOff), local Docker pushes use artifact.it.att.com without port 22609, and Azure Container Apps image pulls use artifact.it.att.com:22609 because ACA outbound pulls require the port-qualified registry endpoint."
---

# Azure Container App Image Routing

Use this workflow whenever building or deploying JANUS container images.

## Platform Rule (build for linux/amd64)

Azure Container Apps runs `linux/amd64`. Docker Desktop on Apple Silicon builds `linux/arm64` by default, and ACA reports the resulting failure as a misleading `ImagePullBackOff` rather than an architecture error.

Always build the Go binaries and the images for amd64:

```bash
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -mod=mod -o build/janus-orchestration-worker ./cmd/worker
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -mod=mod -o build/janus-orchestration-api ./cmd/api

docker build --platform linux/amd64 --provenance=false --target worker -t "$REGISTRY/worker:$TAG" .
docker build --platform linux/amd64 --provenance=false --target api -t "$REGISTRY/api:$TAG" .
```

Requirements:

- `--platform linux/amd64` on every `docker build`, even when the Go binary is already cross-compiled. The Dockerfile only copies a binary, so the base image architecture is what ACA rejects.
- `--provenance=false` keeps the push as a single-architecture manifest instead of an OCI index with an `unknown/unknown` attestation entry.
- The Dockerfile expects prebuilt binaries in `build/`. Rebuild them before `docker build`, otherwise a stale binary ships silently through Docker layer cache.

Verify before deploying:

```bash
docker image inspect "$REGISTRY/worker:$TAG" --format '{{.Os}}/{{.Architecture}}'
```

The output must be `linux/amd64`. If it prints `linux/arm64`, do not deploy; rebuild with `--platform linux/amd64`.

## Registry Routing Rule

The registry hostname differs depending on direction:

- Local machine push target:
  - `artifact.it.att.com/apm0047460-dkr-stage/janus-orchestration/...`
  - Do not use port `22609` for local `docker login`, `docker build -t`, or `docker push`.

- Azure Container Apps pull target:
  - `artifact.it.att.com:22609/apm0047460-dkr-stage/janus-orchestration/...`
  - Azure Container Apps must use port `22609` in the image reference and registry configuration.

## Why

Azure Container Apps cannot currently pull directly from `artifact.it.att.com` without the port-qualified endpoint. Its outbound connection is reset during image pull unless the registry is addressed as `artifact.it.att.com:22609`.

## Required Behavior

When pushing from the current machine:

- Use:
  - `artifact.it.att.com/apm0047460-dkr-stage/janus-orchestration/worker:<tag>`
  - `artifact.it.att.com/apm0047460-dkr-stage/janus-orchestration/api:<tag>`

When configuring Azure Container Apps deployment payloads:

- Use:
  - `artifact.it.att.com:22609/apm0047460-dkr-stage/janus-orchestration/worker:<tag>`
  - `artifact.it.att.com:22609/apm0047460-dkr-stage/janus-orchestration/api:<tag>`

## Deployment Checklist

1. Rebuild the Linux binaries with `GOOS=linux GOARCH=amd64 CGO_ENABLED=0`.
2. Build images with `--platform linux/amd64 --provenance=false`.
3. Confirm `docker image inspect ... --format '{{.Os}}/{{.Architecture}}'` reports `linux/amd64`.
4. Push images locally without port `22609`.
5. Use a new tag per deploy instead of overwriting an existing one.
6. Keep ACA image references and registry server values port-qualified with `:22609`.
7. Verify ACA revision rollout after deployment.

## Verifying a Rollout

Do not trust `provisioningState: Succeeded` alone. It only means the app resource was updated, not that the new revision started.

Check the newest revision instead:

- `runningState` must be `Running`
- `healthState` must be `Healthy`
- `latestReadyRevisionName` must equal `latestRevisionName`

If a revision reports `ActivationFailed`, read the replica container `runningStateDetails`. `ImagePullBackOff` almost always means the image was built for the wrong architecture, or the tag was overwritten after the first push.
