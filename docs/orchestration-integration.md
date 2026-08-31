# Orchestration integration contract

## Purpose and ownership

Control Translation owns only the final translation step. Orchestration owns candidate-loop execution and supplies exact, authoritative Databricks references for the latest Defense Generation, Mitigation Check, and Bypass Validation results.

Control Translation does not query for “the latest” row, mutate upstream tables, rerun an upstream capability, deploy a generated control, or reinterpret `loop_exhausted` as a Bypass Validation terminal state.

## Endpoint

```text
POST /invoke
Content-Type: application/json
```

Use `schemas/request.schema.json` as the machine-readable request contract and `schemas/result.schema.json` as the response contract. Generate a unique `request_id` and stable `idempotency_key` for each semantic invocation. Retries must reuse the same idempotency key and unchanged request body. The API generates missing request and correlation IDs as a defensive fallback, but orchestration should provide stable values for traceability.

### Temporal callers

Call this HTTP endpoint from a Temporal Activity, not from deterministic
Workflow code. Put the Activity invocation behind bounded timeout and retry
policies. Reuse the same request body, `request_id`, `correlation_id`, and
`idempotency_key` on every retry so an uncertain network response cannot create
a new semantic invocation. Retry HTTP 503 and transient transport errors with
backoff; do not retry HTTP 409 or 422 unchanged.

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

## Response handling

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

The semantic request hash includes input, all upstream references, routing metadata, scope configuration, subject revision, and provenance. It excludes transport retry identifiers. Reusing an idempotency key with the same request returns the original result; changing a reference or route under the same key returns `409`.

Completed requests are persisted before success is returned:

- local/dev default: SQLite at `DATABASE_PATH`;
- shared deployment: `36889_janus_dev.control_translation.control_translation_results` when `PERSISTENCE_BACKEND=databricks`.

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
