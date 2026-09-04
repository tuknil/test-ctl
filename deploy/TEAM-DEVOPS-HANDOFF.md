# Control Translation — DevOps handoff

**Repository:** `ATT-CSO/apm0047460-Janus-control-translation`
**JANUS capability:** `control-translation`
**Deployment target:** Azure Container Apps behind approved internal ingress
**Status:** Deployable for a controlled internal POC; not approved for direct Internet exposure or autonomous control deployment.

**Current release:** fixes the deployed Databricks
`request_id` NOT NULL write failure and adds safe end-to-end diagnostics. See
`deploy/RELEASE-HANDOFF.md` before rollout.

This service generates and validates control-specific **candidates**. It does
not deploy Akamai, firewall, or EDR controls.

## Deployment decision

| Area | Required configuration |
|---|---|
| Image | Build from `Dockerfile`; deploy immutable image digest or release tag |
| Container port | `8000` |
| Ingress | Internal/private gateway with TLS, authentication, authorization, rate limits, and audit logging |
| Persistence | Databricks SQL: `36889_janus_dev.control_translation.control_translation_results` |
| Databricks identity | OAuth M2M service principal; PAT is local-testing-only |
| Initial scale | Minimum and maximum replicas set to `1` |
| Liveness | `GET /health` |
| Readiness | `GET /ready` |
| Candidate data | Treat as sensitive; redact in logs and protect dashboard/result routes |

## Required non-secret environment variables

```dotenv
RUN_MODE=live
MODEL_PROVIDER=att-inference
MODEL_NAME=<APPROVED_ATT_MODEL_ID>
ATT_INFERENCE_BASE_URL=<APPROVED_OPENAI_COMPATIBLE_BASE_URL>
MODEL_REQUEST_TIMEOUT_SECONDS=60

PERSISTENCE_BACKEND=databricks
DATABRICKS_SERVER_HOSTNAME=adb-7405605071306757.17.azuredatabricks.net
DATABRICKS_HTTP_PATH=/sql/1.0/warehouses/866109ed7dfce51a
DATABRICKS_AUTH_TYPE=oauth-m2m
DATABRICKS_CLIENT_ID=<DATABRICKS_SERVICE_PRINCIPAL_APPLICATION_ID>
DATABRICKS_CATALOG=36889_janus_dev
DATABRICKS_SCHEMA=control_translation
DATABRICKS_RESULTS_TABLE=control_translation_results
CAPABILITY_CALLBACK_ALLOWED_HOSTS=<APPROVED_ORCHESTRATION_API_HOSTNAME>
CAPABILITY_CALLBACK_TIMEOUT_SECONDS=10
CAPABILITY_CALLBACK_POLL_INTERVAL_SECONDS=1

HOST=0.0.0.0
PORT=8000
ENABLE_DOCS=false
```

## Required secrets

Create secrets in the approved Azure secret store and map them to identically
named container environment variables. Do not put their values in source,
image build arguments, tickets, chat, logs, or a tracked `.env` file.

| Container variable | Source |
|---|---|
| `ATT_INFERENCE_API_KEY` | Approved AT&T Inference secret |
| `DATABRICKS_CLIENT_SECRET` | Databricks OAuth M2M service-principal secret |
| `CAPABILITY_CALLBACK_TOKEN` | Shared orchestration callback bearer secret |

The local PAT setting `DATABRICKS_AUTH_TYPE=pat` / `DATABRICKS_TOKEN` is not
an approved Azure deployment authentication design. Use OAuth M2M in Azure.

## Databricks prerequisites

Before deploying, grant the service principal:

- `CAN USE` on SQL warehouse `866109ed7dfce51a`;
- `USE CATALOG` on `36889_janus_dev`;
- `USE SCHEMA` on `36889_janus_dev.control_translation`;
- `SELECT` and `MODIFY` on `control_translation_results`.

The application writes the validated request, structured result, full response
envelope, hashes/sizes, evidence references, and upstream proof references.
It returns a successful invocation only after persistence succeeds.

`POST /invoke` now generates a UUID `request_id` and `correlation_id` when a
caller omits either value. Caller-provided values are preserved. This fixes the
previous case where connectivity and `/ready` succeeded but Databricks rejected
the completion because its `request_id` column is non-nullable.

## Azure Container Apps settings

- **Target port:** `8000`
- **Transport:** HTTP/auto
- **Min replicas:** `1`
- **Max replicas:** `1`
- **Liveness probe:** `/health`, 10-second initial delay, 30-second period,
  5-second timeout, 3 failures
- **Readiness probe:** `/ready`, same settings
- **Initial resources:** `0.5 vCPU`, `1 GiB` memory; tune from telemetry
- **Volume mount:** durable `/app/data` mount required for lifecycle state,
   including when `PERSISTENCE_BACKEND=databricks`.

One replica is required while lifecycle coordination uses SQLite.

## Release sequence

1. Rotate any credential that was exposed outside the secret store.
2. Run unit tests and build the image in CI using the project Python 3.11/3.12
   toolchain.
3. Scan dependencies and the image, then publish an immutable image reference.
4. Configure non-secret values and secret references in Azure Container Apps.
5. Verify Databricks SQL and Unity Catalog grants for the service principal.
6. Deploy one internal fixture-mode revision first, with the Databricks backend.
7. Check `/health`, `/ready`, `/schema`, and `GET /v1/runs?limit=1` through the
   approved gateway.
8. Submit one fixture `/invoke` request with a unique `idempotency_key`.
   Deliberately omit `request_id` for this first smoke test.
9. Verify the result appears through `/v1/runs`, `/runs/{run_id}`, and
   `/v1/results/{result_id}`, plus exactly one Databricks row.
10. Repeat the same request/key and verify it returns the original IDs; change
    semantic input with the same key and verify HTTP `409`.
11. Enable live AT&T Inference only after the storage smoke test succeeds.
12. Review redacted application logs, Databricks audit logs, and owner approval
    before promotion.

Do not treat `/ready` or a successful `SELECT` as proof that writes work. The
release gate is a successful `/invoke` followed by durable read-back. Logs must
contain `Invocation durably persisted` and must not contain the former
`DELTA_NOT_NULL_CONSTRAINT_VIOLATED` error.

## Rollback

1. Retain the previous image digest and configuration revision.
2. Roll back the application revision; do not restore revoked credentials.
3. Validate `/health`, `/ready`, and one fixture request.
4. If a model issue occurs, use approved fixture mode only as a demo fallback;
   do not represent fixture candidates as live results.

## Handoff references

- Current release/root-cause handoff: `deploy/RELEASE-HANDOFF.md`
- Detailed deployment runbook: `deploy/DEPLOYMENT.md`
- Databricks data/authentication runbook: `docs/databricks-persistence.md`
- Architecture and persistence design: `docs/LLD.md`
- Current security/production follow-ups: `docs/assumptions-and-followups.md`
