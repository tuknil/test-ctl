# Control Translation — write-failure fix release handoff

## Release purpose

This release fixes the deployed Databricks write failure observed after a
successful connection to the SQL warehouse:

```text
[DELTA_NOT_NULL_CONSTRAINT_VIOLATED] NOT NULL constraint violated for column: request_id
```

The failure was not a Databricks connectivity or token-validation failure. The
browser form omitted the optional request identifier, the API generated only a
correlation identifier, and the result table requires `request_id` to be
non-null. A previous developer smoke test supplied `request_id` explicitly and
therefore did not expose the defect.

## Application changes

- `POST /invoke` now generates UUID values for missing `request_id` and
  `correlation_id` before request hashing, translation, logging, and durable
  persistence.
- Caller-provided identifiers remain unchanged.
- Databricks, upstream-resolution, provider, SQLite, and API failure paths now
  emit structured operational logs with complete server-side tracebacks.
- SQL parameter values, authorization values, credentials, idempotency keys,
  and candidate artifact content are not written to diagnostic logs.
- Storage-related HTTP 503 responses include a sanitized diagnostic object with
  operation, backend, safe request/run/result identifiers, error type, and root
  cause. Stack traces remain server-side.
- The demo UI renders the sanitized diagnostic object so deployment failures
  can be correlated with container logs.

## Validation completed before handoff

- Complete automated suite: `85 passed`.
- Browser-form invocation without `request_id`: HTTP 200.
- Live AT&T Inference evidence: `llm_invoked=true`.
- Databricks completion write: succeeded.
- Durable run history refresh: succeeded.
- Caller-provided request ID preservation and generated request ID behavior are
  covered by regression tests.
- Diagnostic redaction and Databricks logging are covered by tests.

Local success proves the application path and target-table mapping with the
configured developer identity. DevOps must still validate the deployed service
identity, secret references, image digest, and new revision.

## Deployment requirements

1. Build from the commit containing this handoff and deploy an immutable image
   tag or digest. Do not reuse a cached image from the previous revision.
2. Retain the approved AT&T Inference and Databricks secret references. Rotate
   any credential previously exposed outside the approved secret store.
3. Use Databricks OAuth M2M for Azure. A PAT is for temporary local validation
   only.
4. Confirm SQL warehouse `CAN USE`, catalog/schema usage, upstream-table
   `SELECT`, and result-table `SELECT` plus `MODIFY` grants.
5. Start with one writer replica.
6. Route traffic to the new revision only after the smoke tests below pass.

The service produces a reviewable control candidate only. It does not deploy a
rule to Akamai, a firewall, SentinelOne, or another target platform.

## Post-deployment smoke test

1. Record the deployed image digest and Container Apps revision name.
2. Verify `GET /health`, `GET /ready`, and `GET /inference` return HTTP 200.
3. Submit a normal browser-form request without manually adding `request_id`.
4. Verify `POST /invoke` returns HTTP 200 and a non-empty `correlation_id`,
   `run_id`, and `result_id`.
5. Verify container logs contain `Invocation durably persisted` and do not
   contain `DELTA_NOT_NULL_CONSTRAINT_VIOLATED`.
6. Verify the result appears in `GET /v1/runs` and can be retrieved through
   `GET /v1/results/{result_id}`.
7. Submit an orchestration request using exact Defense Generation, Mitigation
   Check, and Bypass Validation references.
8. Verify a validated route reports `route=validated` and a 10/10 exhaustion
   route reports `route=poc-exhaustion`, `bypass_cleared=false`,
   `terminal_state=translated`, and an explicit not-bypass-cleared limitation.
9. Verify no response or log contains credentials, authorization headers, raw
   idempotency keys, or candidate artifact content in general diagnostic logs.

`GET /ready` validates configuration and storage connectivity; it does not
replace the write smoke test. The release is accepted only after step 6.

## Orchestration and Temporal usage

Orchestration calls `POST /invoke` after either supported proof-loop route.
Temporal should call it from an Activity rather than Workflow code. Provide a
stable `request_id`, `correlation_id`, and `idempotency_key` for deterministic
retries. The API generates missing request and correlation IDs as a safety net,
but generated IDs are not a replacement for orchestration-owned retry
identity.

Retry HTTP 503 and transient network failures with bounded backoff while
reusing the same request body and idempotency key. Do not retry HTTP 409 or 422
unchanged. Route HTTP 200 responses by `terminal_state`, not HTTP status alone.

See `docs/orchestration-integration.md` for the complete contract.

## Failure triage

For a storage HTTP 503:

1. Capture the response diagnostic's operation, request ID, correlation ID,
   run ID, result ID, and error type. Do not paste secrets into a ticket.
2. Correlate those identifiers with the Container Apps logs; the full traceback
   is logged there.
3. If `/ready` fails, check configuration, secret references, warehouse state,
   DNS/network path, and grants.
4. If `/ready` passes but `/invoke` fails, inspect the write-specific root cause
   and target-table constraints. Do not assume that readiness proves writes.
5. Confirm the active revision uses the new image digest before reopening the
   application defect.

## Rollback

Retain the prior image digest. If the new revision fails unrelated smoke tests,
shift traffic back to the prior revision without restoring revoked credentials.
The prior revision still contains the missing-request-ID defect, so it is not a
valid long-term rollback for browser-form or caller requests that omit that
field.
