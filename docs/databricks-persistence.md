# Databricks persistence runbook

## Target

The Azure deployment uses the existing table:

`36889_janus_dev.control_translation.control_translation_results`

Workspace hostname: `adb-7405605071306757.17.azuredatabricks.net`
SQL warehouse HTTP path: `/sql/1.0/warehouses/866109ed7dfce51a`

SQLite remains the default for local development and unit tests.

## Authentication and authorization

The managed Azure deployment uses Databricks OAuth M2M through a service
principal. Temporary local validation may use a PAT. Inject
`DATABRICKS_CLIENT_SECRET` or `DATABRICKS_TOKEN` from an approved secret source.
Do not put either secret in `.env.example`, source control, build arguments,
chat, logs, or tickets. A local ignored `.env` is acceptable only for temporary
developer testing and must have access restricted to the developer account.

The service principal requires:

- `CAN USE` on SQL warehouse `866109ed7dfce51a`;
- `USE CATALOG` on `36889_janus_dev`;
- `USE SCHEMA` on `36889_janus_dev.control_translation`;
- `SELECT` and `MODIFY` on `control_translation_results`.

Use least privilege and confirm grants with the Databricks owner before the
first live smoke test.

## Runtime settings

```dotenv
PERSISTENCE_BACKEND=databricks
DATABRICKS_SERVER_HOSTNAME=adb-7405605071306757.17.azuredatabricks.net
DATABRICKS_HTTP_PATH=/sql/1.0/warehouses/866109ed7dfce51a
DATABRICKS_AUTH_TYPE=oauth-m2m
DATABRICKS_CLIENT_ID=<SERVICE_PRINCIPAL_APPLICATION_ID>
DATABRICKS_CLIENT_SECRET=<INJECTED_SECRET_REFERENCE>
DATABRICKS_CATALOG=36889_janus_dev
DATABRICKS_SCHEMA=control_translation
DATABRICKS_RESULTS_TABLE=control_translation_results
```

`DATABRICKS_CLIENT_ID` is not a secret, but it must still come from approved
deployment configuration. The actual client secret must not be shared with the
application team through chat.

For temporary local PAT testing, replace only the authentication settings:

```dotenv
DATABRICKS_AUTH_TYPE=pat
DATABRICKS_TOKEN=<LOCAL_IGNORED_ENV_ONLY>
```

`DATABRICKS_CLIENT_ID` and `DATABRICKS_CLIENT_SECRET` are not required in PAT
mode. Revoke the PAT after testing or immediately if it was copied into a
tracked file, chat, terminal output, ticket, or screen share.

## Data mapping

- `request_json`: complete validated invocation envelope, including optional
  `idempotency_key` and `subject_record_revision_id`.
- `result_json`: exact structured `ControlTranslationResult` JSON.
- `completion_json`: complete `ResultEnvelope` returned by `/invoke`.
- `result_sha256` and `result_size_bytes`: SHA-256 and UTF-8 size of the exact
  `result_json` bytes.
- `evidence_refs`: deduplicated evidence and result provenance references.
- `upstream_result_refs`: upstream proof-record IDs.
- `created_at`: UTC invocation start time.

All SQL values use parameter markers. Catalog, schema, and table identifiers
are restricted to letters, digits, and underscores before being quoted.
Successful API completion is returned only after the Databricks write succeeds.

The target table requires a non-null `request_id`. The API normalizes every
invocation before hashing or persistence: it preserves a caller-supplied value
or generates a UUID when the field is omitted. The same rule applies to
`correlation_id`.

## Idempotency limitation

No table migration is required for the initial integration. Idempotency lookup
filters the key within `request_json`, reloads the request, and recomputes its
canonical hash in Python. This preserves same-key/same-request replay and
same-key/different-request HTTP `409` behavior.

The existing table does not enforce a unique idempotency key. Run one Azure
Container Apps replica initially. Do not enable horizontal writer scaling until
a unique-key, lock, or orchestration-level serialization strategy is approved.

## Deployment validation

1. Set non-secret values and inject the selected authentication secret.
2. Deploy one replica behind the approved internal gateway.
3. Confirm `GET /health` returns `200`.
4. Confirm `GET /ready` returns `200`. This confirms connection/read health,
   not write compatibility.
5. Submit one approved fixture invocation with a unique `idempotency_key` but
   omit `request_id` to exercise server-side normalization.
6. Confirm the response is present in `GET /v1/runs` and
   `GET /v1/results/{result_id}`.
7. Confirm exactly one target-table row exists and its hash/size match
   `result_json`.
8. Repeat the request with the same idempotency key and verify the original
   `run_id` and `result_id` are returned.
9. Reuse the key with changed semantic input and verify HTTP `409`.
10. Review application and Databricks audit logs for secret or candidate-data
    leakage before promotion.

For write failures, correlate the sanitized HTTP 503 diagnostic identifiers
with container logs. The application logs the operation, table, SQL statement
type, duration, parameter count, Databricks error metadata, and traceback, but
never SQL parameter values or credentials.

The previously observed error
`DELTA_NOT_NULL_CONSTRAINT_VIOLATED: request_id` was an application
normalization defect, not evidence of a bad token. A successful connection or
`SELECT` does not prove that a row satisfies target-table constraints.
