# Orchestration integration contract

## Purpose and ownership

Control Translation owns only the final translation step. Orchestration owns candidate-loop execution and supplies exact, authoritative Databricks references for the latest Defense Generation, Mitigation Check, and Bypass Validation results.

Control Translation does not query for “the latest” row, mutate upstream tables, rerun an upstream capability, deploy a generated control, or reinterpret `loop_exhausted` as a Bypass Validation terminal state.

## Endpoints

```text
POST /v1/control-translation-runs
GET  /v1/control-translation-runs/{run_id}
GET  /v1/control-translation-runs/{run_id}/result
POST /v1/control-translation-runs/{run_id}/cancel
Content-Type: application/json
Idempotency-Key: <request_id>
X-Correlation-ID: <correlation_id>
```

Generate a unique stable `request_id` for each semantic invocation. It must
equal `Idempotency-Key`; body `correlation_id` must equal `X-Correlation-ID`.
Retries reuse all three identities and an unchanged request body. Submission
returns `202` for queued/running work and may return `200` when an identical
retry resolves to an already-terminal run. Poll status at low frequency, then
fetch the immutable result after terminal status. `409 run_not_terminal` from
the result endpoint is non-retryable until a later status poll observes a
terminal state. For a terminal `failed` or `canceled` run that has no service
result, the result endpoint returns HTTP `200` with the same
`capability-run-status@1.0` terminal status envelope.

`POST /invoke` remains temporarily available as the synchronous compatibility
facade. New Temporal integration must use the lifecycle endpoints.

### Temporal callers

Call each HTTP endpoint from a Temporal Activity, not from deterministic
Workflow code. Use separate Submit, GetStatus, and GetResult Activities with
bounded timeouts. Do not repeatedly submit while waiting. Reuse the same body
and headers only when retrying an uncertain Submit response. Retry `408`,
`425`, `429`, `5xx`, and transient transport failures with backoff. Treat
validation, authentication, not-found, and idempotency conflict responses as
non-retryable unless their error envelope explicitly says otherwise.

## Authoritative source tables

The service reads exactly one `result_id` from each reference supplied by orchestration.

| Role | Unity Catalog table | Physical payload shape read by Control Translation | Required state |
|---|---|---|---|
| Defense Generation | `36889_janus_dev.defense_generation.defense_generation_results` | `result_id`, `terminal_state`, `request_json` VARIANT, `result_json` VARIANT | `candidate-produced` |
| Mitigation Check | ``36889_janus_dev.`mitigation-check`.mitigation_check`` | `result_id`, `result_json` JSON string | `blocked` |
| Bypass Validation | `36889_janus_dev.bypass_validation.bypass_validation_results` | `result_id`, `terminal_state`, `correlation_id`, `request_json` JSON string, `result_json` JSON string | Route-dependent |

Identifiers are validated before interpolation and result IDs are passed as SQL parameters. No broad scan or “latest row” fallback is used.

The three records must resolve to one unambiguous value for each of:

- `correlation_id`, equal to the invocation envelope value;
- `subject_record_revision_id`, equal to the invocation envelope value;
- `vulnerability_id`, equal across all three records;
- `candidate_id`, equal across all three records.

Defense Generation must also supply a primary candidate containing the selected control class, discriminator, and artifact content. Missing, conflicting, or ambiguous lineage returns `insufficient-context`; Control Translation never guesses.

## Accepted routes

### Validated route

Use this route when the authoritative Bypass Validation result is `no-bypass-found`.

- `loop_exhausted`: `false`
- `bypass_validation_terminal_state`: `no-bypass-found`
- `completed_iterations`: at least 1 and no greater than `max_iterations`
- `max_iterations`: configured orchestration maximum

The result reports:

- `proof_loop_qualification.route: validated`
- `proof_loop_qualification.bypass_cleared: true`

“Cleared” remains bounded to the upstream Bypass Validation profile; it is not a production-safety or universal unbypassability claim.

### PoC exhaustion route

Use this route only when the latest authoritative Bypass Validation result is `bypass-found` and orchestration completed all 10 configured candidate cycles.

- `loop_exhausted`: `true`
- `completed_iterations`: `10`
- `max_iterations`: `10`
- `bypass_validation_terminal_state`: `bypass-found`

The result reports:

- `terminal_state: translated` when the target translation succeeds
- `proof_loop_qualification.route: poc-exhaustion`
- `proof_loop_qualification.bypass_cleared: false`
- the actual `bypass-found` state, counts, and authoritative result reference
- a primary-candidate limitation stating that it is not bypass-cleared
- the bounded bypass counterexample and evidence references, when present

This is a temporary PoC behavior. A translated exhaustion result means only
that the latest candidate was expressed for the target technology; it does not
erase the bypass finding or make the candidate production-ready.

## Complete validated-route request

```json
{
  "input": {
    "target_context": {
      "target_technology": "akamai-waf",
      "target_policy_context_id": "akamai-policy:example:rev-17"
    }
  },
  "request_id": "control-translation-request:example-001",
  "correlation_id": "janus-correlation:example-001",
  "idempotency_key": "control-translation:example-001:validated",
  "subject_record_revision_id": "canonical-vulnerability-revision:example-001",
  "upstream_result_refs": {
    "defense_generation": {
      "system": "databricks",
      "catalog": "36889_janus_dev",
      "schema": "defense_generation",
      "table": "defense_generation_results",
      "key": "defense-generation-result:example-001"
    },
    "mitigation_check": {
      "system": "databricks",
      "catalog": "36889_janus_dev",
      "schema": "mitigation-check",
      "table": "mitigation_check",
      "key": "mitigation-check-result:example-001"
    },
    "bypass_validation": {
      "system": "databricks",
      "catalog": "36889_janus_dev",
      "schema": "bypass_validation",
      "table": "bypass_validation_results",
      "key": "bypass-validation-result:example-001"
    }
  },
  "routing_metadata": {
    "loop_exhausted": false,
    "completed_iterations": 4,
    "max_iterations": 10,
    "bypass_validation_terminal_state": "no-bypass-found",
    "bypass_validation_result_ref": {
      "system": "databricks",
      "catalog": "36889_janus_dev",
      "schema": "bypass_validation",
      "table": "bypass_validation_results",
      "key": "bypass-validation-result:example-001"
    }
  },
  "provenance": {
    "caller": "janus-orchestration",
    "source": "candidate-proof-loop"
  }
}
```

For the exhaustion route, use the same structure but set the four routing values to `true`, `10`, `10`, and `bypass-found`. The routing bypass reference must exactly equal `upstream_result_refs.bypass_validation`.

## Target selection

Caller values take precedence. If either target field is absent, the service fills it from:

- `DEFAULT_TARGET_TECHNOLOGY` (default `akamai-waf`)
- `DEFAULT_TARGET_POLICY_CONTEXT_ID` (default `akamai-policy:example:rev-17`)

`input_bindings.configured_poc_defaults_used` tells orchestration whether either configured default was used. For controlled integration, orchestration should send both target fields explicitly.

One invocation emits at most one `primary_candidate`.

## Lifecycle response handling

Submission is intentionally compact. Status is side-effect free and reports
`queued`, `running`, `completed`, `failed`, or `canceled`. A completed status
contains `completion` with the canonical result identity/reference and content
integrity. A failed status contains stable `failure.code`, operator-safe detail,
and retryability. The full candidate is not embedded in status.

Cancellation is idempotent. Queued work and running work that has not crossed
the durable publication cutoff become canceled immediately and relinquish the
lease. Provider calls that cannot be interrupted are detached in a daemon
attempt thread; their eventual output is fenced and cannot publish. Once
publication is pending, an external write may already have succeeded, so a
late cancellation is recorded but cannot hide the canonical completion.
Canceling a terminal run returns that unchanged terminal status.

The compatibility `/invoke` handling remains:

| HTTP/result condition | Orchestration action |
|---|---|
| HTTP `200`, `translated` | Continue to review/defense validation; inspect `proof_loop_qualification` before routing |
| HTTP `200`, `cannot-express` | Select another supported target or retain typed residual |
| HTTP `200`, `insufficient-context` | Repair missing record, lineage, policy context, resolver configuration, or upstream state and retry |
| HTTP `200`, `scope-declined` | Do not retry unchanged; target/class/policy is outside coverage or conflicts |
| HTTP `200`, `malfunction` | Retry according to orchestration policy, then escalate |
| HTTP `409` | Idempotency key was reused with different semantic input; issue a new key or restore the original body |
| HTTP `422` | Contract/routing metadata is malformed; fix before retrying |
| HTTP `503` | Durable storage is unavailable or deployment is not ready; retain the sanitized diagnostic identifiers, retry with backoff, and correlate with server logs |

A `200` response is a completed capability result, not necessarily a successful translation. Route on `terminal_state`, not HTTP status alone.

## Idempotency and persistence

The lifecycle normalized SHA-256 includes the complete validated semantic body,
including request/correlation identity, input, exact upstream references,
routing context, subject, and provenance. It excludes only the duplicated body
`idempotency_key` transport field. Reusing a key with the same digest returns
the original run; changing any semantic field returns
`409 idempotency_conflict`.

Completed requests are persisted before success is returned:

- lifecycle state: SQLite at `DATABASE_PATH` (deployment path
  `/app/data/control_translation.db`) on a durable mounted volume;
- immutable result sink: `control_translation_results` when
  `PERSISTENCE_BACKEND=databricks`.

SQLite uses `DELETE` journaling and the service must run exactly one replica.
Workers persist owner ID, lease expiry, heartbeat, and attempt number. Every
worker-owned write is fenced by owner and attempt. Expired leases are reclaimed
using the same run identity, and bounded attempt exhaustion becomes
`failed/worker_attempts_exhausted` rather than a permanently running row.

Before Databricks publication, the worker stages the exact result envelope,
canonical result, completion metadata, identity, digest inputs, and timestamps
in SQLite under the active lease fence. It then atomically changes the outbox
from `prepared` to `publication-pending`, performs the idempotent Databricks
`MERGE`, verifies the existing or inserted row, and atomically finalizes the
lifecycle row. Recovery of `publication-pending` work reuses the staged bytes
without invoking translation again. Publication-pending recovery is not
discarded by the normal generation-attempt bound because an external row may
already exist and must remain visible through canonical completion.

For async runs, the canonical integrity representation is UTF-8 JSON with
lexicographically sorted object keys, compact separators, unescaped Unicode,
and `content_sha256` and `size_bytes` omitted to avoid self-reference. Those
exact bytes are stored in Databricks `result_json`; `result_sha256` and
`result_size_bytes` cover those bytes. Lifecycle completion reports the same
digest with a `sha256:` prefix and the same byte count.

The Databricks row's `contract_id`, `status`, and `terminal_state` are sourced
from this canonical async result and verified on readback. They are therefore
`control-translation-result@1.0`, `completed`, and one of `translated`,
`not-translatable`, or `malfunction`, rather than compatibility-envelope state
values. A translated result stores exact artifact content at
`result_json.artifacts.primary.content`; `primary_candidate.content_ref` is a
stable `databricks://` URI identifying that row, column, and JSON location.
It never points to the legacy full-result HTTP API.

The Databricks result row stores request, structured result, complete response envelope, evidence/upstream references, hashes, sizes, and timestamps. `GET /runs/{run_id}` and `GET /v1/results/{result_id}` read the durable completion.

Missing `request_id` and `correlation_id` values are generated before the
semantic hash and persistence operation. This guarantees a non-null Databricks
`request_id`, while preserving caller-provided identifiers. Stable
orchestrator-provided identifiers remain recommended because server-generated
values cannot be known before an uncertain retry.

## Security and permissions

The service identity requires `CAN USE` on SQL warehouse `866109ed7dfce51a`, `USE CATALOG` on `36889_janus_dev`, `USE SCHEMA` plus `SELECT` on all three source schemas/tables, and `SELECT` plus `MODIFY` on the Control Translation result table. OAuth M2M is the deployment default; PAT is local validation only.

Do not send Databricks credentials in invocation JSON. Put the API behind authenticated internal ingress. Treat candidate content and upstream JSON as sensitive security data and redact it from general-purpose logs.

## Known boundary

Upstream retrieval, proof/lineage gating, translation, and durable result persistence are implemented. Current target policy readers remain fixture-backed; a `translated` result is a reviewable target-specific candidate, never an automatic deployment or production approval.
