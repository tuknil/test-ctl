# Low-Level Design — control-translation service

## 1. Purpose & scope

Implements the `control-translation` CFS (see `docs/cfs-source.md`): turns a
proven mitigation pattern into a control-specific mitigation candidate for a
target technology, or emits a grounded non-positive terminal state. Scope of
this build: Akamai WAF, PAN-OS firewall, and a SentinelOne (S1) STAR EDR
target, all fixture-backed (real documented syntax, no live tenant), with a
real Pydantic AI agent as the translation doer.

## 2. Component diagram

```text
                 ┌────────────────────┐
   HTTP client   │   FastAPI api.py    │   API only; the demo UI is a
  ───────────►   │  /health /schema    │   separate service (see §12)
                 │ /invoke /v1/control │
                 │ -translation-runs   │
                 │ /v1/runs /results   │
                 │ /runs/{id} /results │
                 └─────────┬───────────┘
                           │
                 ┌─────────▼───────────┐
                           │   capability.py     │  capability + terminal routing
                 └───┬─────────────┬───┘
                     │             │
                       ├───────────────┼──────────────────────────┐
                       │               │                          │
                     ┌──────▼──────────┐ ┌──▼──────────────┐   ┌──────▼─────────────┐
                     │ upstream.py     │ │ policy_reader   │   │ translation/engine │
                     │ lineage/route   │ │ (fixture only)  │   │  ├─ adapters/*     │
                     │ validation      │ └─────────────────┘   │  ├─ agents/        │
                     └──────┬──────────┘                       │  ├─ syntax judge   │
                       │                                  │  └─ conflict judge │
                     ┌──────▼────────────────┐                 └────────────────────┘
                     │ upstream_databricks.py│
                     │ exact result-id reads │
                     └──────┬────────────────┘
                       │
                     ┌──────▼───────────────────────────────────────────────────────┐
                     │ Defense Generation | Mitigation Check | Bypass Validation   │
                     └──────────────────────────────────────────────────────────────┘

                 ┌──────────────────────────────────────────────┐
                 │ Durable lifecycle + callback outbox          │
                 │ SQLite /app/data transaction                 │
                 └──────────────────────┬───────────────────────┘
                                        │ asynchronous retry
                 ┌──────────────────────▼───────────────────────┐
                 │ callbacks.py → orchestration callback API    │
                 └──────────────────────────────────────────────┘
```

## 3. Data models

See `src/control_translation/contracts.py` for the full Pydantic model set:
`ProvenMitigationPattern`, `TargetContext`, `TranslationPolicy`,
`ControlTranslationRequest`, `ControlTranslationResult` and its
substructures (`Subject`, `InputBindings`, `OutcomeReason`,
`PrimaryCandidate`, `CandidateArtifact`, `ImplementsDiscriminator`,
`Placement`, `CollateralImpactPrior`, `EvidenceBinding`), plus the API
envelope models `InvokeRequestEnvelope` / `ResultEnvelope`, and dashboard
models `RunSummary` / `RunListResponse`. Terminal states and reason codes live
in `terminal.py`.

Referenced invocation additionally uses `UpstreamResultReferences`,
`ProofLoopRoutingMetadata`, and `ProofLoopQualification`. The qualification is
persisted in `ControlTranslationResult` so PoC exhaustion can never be rendered
as full bypass clearance.

## 4. Sequence (happy path)

1. `POST /v1/control-translation-runs` validates the envelope, idempotency
   hash, and optional callback header group. The compatibility route
   `POST /invoke` remains synchronous and does not accept callbacks.
2. For a referenced request, `upstream_databricks.py` parameter-selects the
  exact three result IDs; `upstream.py` validates IDs, route states,
  correlation, subject revision, vulnerability, and candidate lineage.
3. The accepted route is either validated (`no-bypass-found`) or PoC
  exhaustion (`bypass-found` after exactly 10/10 cycles). The latter is
  explicitly marked `bypass_cleared=false`.
4. `capability.invoke_envelope` → `capability.invoke` and resolve the
  `TargetAdapter`; unknown target → `scope-declined`.
5. Call `PolicyReader.read_snapshot`;
   miss → `insufficient-context`.
6. `translation/engine.translate`:
   a. For `akamai-waf`, `_akamai_deterministic_proposal` builds the candidate in
      code, most authoritative source first: the Mitigation Check JSON field,
      an anchored literal argument, the proven form body, then
      `modsec_akamai.compile_akamai_custom_rule`, which compiles the proven
      ModSecurity `SecRule` itself. The path that ran is reported as
      `inference.proposal_source`.
   b. Only if no deterministic path applies:
      `adapter.supports_feature(discriminator_description)` mechanical
      pre-check (fails → `cannot-express`), then the doer
      (`FixtureTranslationDoer` or `LiveTranslationDoer`) →
      `TranslationProposal`; exception → `malfunction` (`provider-failure`).
   c. `syntax_validator.validate` (judge gate 1); fails → `cannot-express`.
   d. `conflict_checker.detect_conflicts` (judge gate 2); non-empty → surfaced
      as `conflict_notes`.
7. Back in `capability.invoke`: if conflicts present → `scope-declined`
   (`policy-conflict`); else assemble `translated` result.
8. `capability._envelope` wraps the result in `ResultEnvelope` with durable
  result/correlation references; `api.py` atomically stores the validated
  request, final envelope, artifact, and evidence references through the
  configured `RunRepository`.

## 5. Adapter interface contract

`adapters/base.py::TargetAdapter` protocol:

- `target_technology`, `artifact_type`, `supported_features`
- `supports_feature(discriminator_description) -> bool`
- `validate_syntax(candidate_content) -> SyntaxValidationResult`
- `detect_conflicts(candidate_content, snapshot) -> list[str]`

Implementations validate the documented real target syntax (see
`docs/syntexresearch.md`); none is vendor-API-backed yet:

- `AkamaiWafAdapter` — Akamai custom-rule JSON (`operation` + `conditions[]`);
  rejects an action embedded in the rule body (action is set separately on
  the security policy).
- `FirewallGenericAdapter` — PAN-OS security rule in CLI
  `set rulebase security rules ...` form or XML `<entry>` form (requires
  from/to zones, source, destination, application, service, action).
- `EdrS1Adapter` — SentinelOne STAR rule JSON
  (`data{name, s1ql, severity, queryLang, treatAsThreat}`); defaults are
  alert-only (`treatAsThreat=UNDEFINED`).

## 6. Terminal-state decision table

| Order | State | Trigger |
|---|---|---|
| 1 | `scope-declined` | Unknown target technology, or a detected policy conflict after translation |
| 2 | `insufficient-context` | No policy snapshot available and none supplied |
| 3 | `cannot-express` | Adapter pre-check fails, or candidate fails syntax validation |
| 4 | `malfunction` | Doer raises an exception, or returns an invalid `translation_label` |
| 5 | `translated` | Candidate produced, passed syntax validation, no conflicts |

Implemented in `capability.py::invoke`; precedence constants declared in
`terminal.py::TERMINAL_STATE_PRECEDENCE` for documentation/testing reference.

## 7. Fixture vs. live-path matrix

| Component | Fixture mode (default) | Live mode (RUN_MODE=live) |
|---|---|---|
| PolicyReader | `FixturePolicyReader`, 2 canned snapshots | Not implemented — no real adapter exists |
| Proven pattern source | Legacy `providers/fixtures.py` direct input or referenced Databricks records | Exact referenced Databricks records, validated by the same resolver/gates |
| Upstream route | Validated and 10-cycle exhaustion tests use injected records | SQL Connector reads the three authoritative Unity Catalog tables |
| Translation doer | `FixtureTranslationDoer`, deterministic templates | `LiveTranslationDoer`, real Pydantic AI agent call, needs `.env` model config |
| Adapters (syntax/conflict) | Deterministic real-format validation (JSON / PAN-OS CLI+XML / STAR JSON) + fixture snapshot comparison | Same code path; not vendor-API-backed either way |

## 8. Error handling & malfunction paths

- Doer exceptions are caught in `translation/engine.translate` and routed to
  `EngineFailure(reason="provider-failure")` → `malfunction`.
- Invalid `translation_label` from the doer is treated as a provider defect
  → `malfunction` (guards against a misbehaving agent silently producing an
  unlabeled candidate).
- FastAPI/Pydantic validation errors on `POST /invoke` are surfaced as HTTP
  422 automatically (request never reaches `capability.invoke`).
- `GET /runs/{run_id}` returns HTTP 404 for unknown run ids.
- `GET /v1/runs` applies validated `limit` (1–100) and non-negative `offset`
  pagination and returns metadata only, ordered newest first.
- Persistence failures return a redacted HTTP 503 and never claim durable
  completion.
- The API generates missing `request_id` and `correlation_id` values before
  request hashing and persistence, while preserving caller-provided values.
- Storage HTTP 503 responses include sanitized operation/backend identifiers
  and root-cause text for UI correlation. Complete tracebacks are emitted only
  to server logs; credentials, SQL parameter values, raw idempotency keys, and
  candidate artifact content are redacted.

## 9. Persistence design

The `RunRepository` boundary has two implementations. `SQLiteRunRepository`
stores normalized run, payload, artifact, and evidence rows in atomic local
transactions and remains the local/test default. `DatabricksRunRepository`
maps each completion to the existing Unity Catalog results table using one
parameterized `MERGE`, JSON `VARIANT` columns, and OAuth M2M. It stores the
structured result separately from the full completion envelope and validates
the envelope again when reading it. `/ready` verifies the selected backend.

Databricks idempotency uses the key inside `request_json`, reloads the stored
request, and recomputes the canonical semantic hash in Python. This avoids a
table migration but does not strongly serialize simultaneous first requests
with the same key. The initial deployment therefore remains one replica until
a unique-key or other concurrency design is approved.

The Databricks result table requires non-null `request_id`. API-boundary
normalization guarantees this constraint for UI and integration callers that
omit the optional transport field. Readiness verifies connection/read health;
deployment acceptance additionally requires a successful write and durable
read-back smoke test.

When callback headers are present, the SQLite lifecycle transaction stores the
callback metadata with the queued run. After immutable result publication, the
same transaction that commits lifecycle status `completed`, `failed`, or
`canceled` inserts one `callback_deliveries` outbox row. In Databricks mode,
Databricks remains the immutable result sink while the `/app/data` SQLite
lifecycle database remains the durable callback outbox. This ordering makes
the canonical status and result available before asynchronous delivery begins.

Each repository's `list_runs` selects a safe projection for the UI: run and
result identifiers, correlation identifier, state/reason, vulnerability,
target, artifact type, and timestamps. It does not load or return stored
request JSON or artifact content. The UI retrieves a full result on demand via
`GET /runs/{run_id}` and renders dashboard values as text rather than HTML.

## 10. Terminal callback delivery

### Submission contract

Both submit routes read these optional headers as one all-or-none group:

- `X-Janus-Callback-URL`
- `X-Janus-Callback-Workflow-ID`
- `X-Janus-Callback-Signal`

If none are present, execution remains polling-only. If any are present, all
three are required. The URL must use HTTPS, contain no embedded credentials or
fragment, and match `CAPABILITY_CALLBACK_ALLOWED_HOSTS` when that allowlist is
configured. The signal must be exactly
`janus.capability-completion.v1`. Only the Temporal workflow ID is accepted;
there is no workflow run ID field.

`CAPABILITY_CALLBACK_TOKEN` is loaded only from the process environment and is
expected to be backed by an Azure Container Apps secret reference. It is never
persisted, logged, or returned. A submit with valid callback headers still
completes when the token is missing. The API logs a redacted configuration
error, persists the canonical result and callback event, and leaves Status and
Result polling available.

### Event and payload

Every terminal result creates at most one logical event with stable ID
`control-translation:<run_id>:terminal:v1`. Existing successful and declined
domain outcomes map to lifecycle `completed`; `malfunction` maps to `failed`.
The callback body is strict and contains no result data or unknown fields:

```json
{
  "workflow_id": "<temporal-child-workflow-id>",
  "wakeup": {
    "event_id": "control-translation:<run-id>:terminal:v1",
    "capability": "control-translation",
    "request_id": "<submit-request-id>",
    "correlation_id": "<correlation-id>",
    "run_id": "<capability-run-id>"
  }
}
```

### Delivery state machine

`callbacks.py::CallbackDispatcher` scans durable due records outside the submit
request. It sends `POST` with `Authorization: Bearer <token>` and
`Content-Type: application/json`. A matching `202` response with only
`event_id` and `status=accepted` marks delivery complete. Network failures and
HTTP `408`, `425`, `429`, `500`, `502`, `503`, and `504` retry. `Retry-After`
is honored. Otherwise retries use jittered delays based on 5 seconds, 15
seconds, 30 seconds, 1 minute, 5 minutes, and then 15 minutes indefinitely,
which exceeds the required 24-hour window.

HTTP `400`, `401`, `404`, and `415` mark the event
`configuration-failed` and emit an alert without logging the token. A `503`
remains retryable. At-least-once duplicate sends are safe because every retry
reuses the same event ID. Callback state never modifies the immutable
canonical result, and polling remains the fallback for every failure mode.

## 11. Agent architecture

- Default doer for `akamai-waf`: **code, not a model.**
  `translation/modsec_akamai.py` compiles the proven ModSecurity rule into an
  Akamai custom rule and returns the same `TranslationProposal` shape. It
  declines (returns `None`) for any construct without a certain Akamai
  equivalent, which is the only way the model is reached for a WAF candidate.
- Fallback doer: `agents/translation_agent.py`. `TranslationProposal` is the
  only trusted output shape from the model.
- Model/provider config: `config.py::Settings`, sourced from `.env`
  (`RUN_MODE`, `MODEL_PROVIDER`, `MODEL_NAME`, `OPENAI_API_KEY` or Azure
  OpenAI equivalents). `RUN_MODE=fixture` is the default and requires no key.
- Judge: `translation/syntax_validator.py` + `translation/conflict_checker.py`,
  both purely deterministic, both delegate the target-specific check to the
  adapter.

## 12. Deployment architecture summary

Two deployables are built from this repository.

**Capability API** (`Dockerfile`): Python 3.11+ runtime,
`uvicorn control_translation.api:app` entrypoint, port 8000, `.env` variables
injected as container secrets (never baked into the image), durable volume at
`/app/data`, exactly one replica while lifecycle state uses SQLite.

**Demo UI** (`Dockerfile.ui`): `uvicorn control_translation_ui.app:app`
entrypoint, port 8080, the static `ui/` directory, and a single setting,
`API_ENDPOINT`. It installs only `deploy/ui-requirements.txt`, so the UI image
carries no model client and no Databricks driver. It is stateless, needs no
volume, and scales horizontally. It must never receive the API's secrets.

The browser loads the page from the UI service and calls the API directly, so
the API's `CORS_ALLOWED_ORIGINS` must name the UI's public origin. That setting
is empty by default, which closes browser access entirely. Alternatively, front
both with one gateway hostname and set `API_ENDPOINT=""` to keep the browser
same-origin.

Full DevOps handoff spec: `deploy/DEVOPS-HANDOFF.html`. Working `Dockerfile`,
`Dockerfile.ui`, `.dockerignore`, and a two-service `docker-compose.yml` are
included in this repo as a starting point for DevOps to adapt.

Callback deployment additionally requires a secret reference for
`CAPABILITY_CALLBACK_TOKEN`. Configure
`CAPABILITY_CALLBACK_ALLOWED_HOSTS` with the approved orchestration API
hostname. Callback token absence does not make `/ready`, `/runs/{run_id}`, or
`/v1/results/{result_id}` unavailable.

## 13. Testing strategy

- **Contract tests** (`tests/test_contract.py`): request model accepts valid
  shape, rejects malformed input.
- **Terminal-state tests** (`tests/test_terminal_states.py`): one test per
  reachable terminal state (`translated`, `scope-declined`,
  `insufficient-context`, `cannot-express`, `malfunction`).
- **API tests** (`tests/test_api.py`): health, schema, invoke, runs
  (found + 404).
- **Adapter tests** (`tests/test_adapters.py`): registry resolution, syntax
  validation pass/fail per adapter, fixture policy reader hit/miss.
- **Agent fixture-mode tests** (`tests/test_agent_fixture_mode.py`):
  `FixtureTranslationDoer` output shape, doer-factory wiring for both
  `fixture` and `live` `RUN_MODE` (live mode is only constructed, never
  invoked, in tests — no API key required).
- **Callback tests** (`tests/test_callbacks.py`): all-or-none header handling,
  HTTPS/signal/allowlist validation, atomic outbox creation, exact wakeup
  payload, stable event IDs, `202` completion, retry/backoff and `Retry-After`,
  configuration alerts, token redaction, duplicate safety, and polling
  availability after callback failure.

All default tests run offline with no network access or API key.

## 14. Assumptions & open questions

See `docs/assumptions-and-followups.md` for the full list.
