# SQLite Persistence Implementation Plan

**Status:** Phase 1 implemented — SQLite persistence and backward-compatible API integration
**Capability:** `control-translation`
**Goal:** Replace process-only run storage with durable SQLite persistence while preserving the current API and test behavior.

## 1. Objectives

The implementation will:

1. Persist every accepted invocation request and its final output.
2. Persist run metadata, result metadata, candidate artifacts, and evidence references.
3. Preserve the current `POST /invoke` response shape during the first migration phase so existing callers and the demo UI do not break.
4. Make `GET /runs/{run_id}` read from SQLite instead of the in-memory `_RUNS` dictionary.
5. Add durable lookup by `result_id` for JANUS integrations.
6. Prepare the response model for a later compact JANUS completion envelope containing `result_id`, `correlation_id`, and `result_ref`.
7. Avoid storing credentials, authorization headers, or environment-variable secrets.

## 2. Current State

- `src/control_translation/api.py` stores completed runs in the process-local `_RUNS` dictionary.
- Data is lost on restart and cannot be shared across replicas.
- `ControlTranslationResult` contains the business `result_id` and final structured output.
- `ResultEnvelope` contains `run_id`, status, terminal state, the complete structured result, provenance, trace, warnings, and inference metadata.
- Candidate rule content is currently placed in `candidate_artifact.content_ref`; despite the name, it contains the generated artifact itself and must therefore be treated as potentially sensitive data.
- The API currently has no `correlation_id`, idempotency contract, database configuration, or migration mechanism.

## 3. Implementation Boundaries

### Included

- Local SQLite database using Python's standard `sqlite3` module.
- Repository abstraction so SQLite can later be replaced by Databricks or another approved system of record.
- Automatic, versioned schema initialization.
- Atomic persistence of an invocation and its final output.
- Durable run and result retrieval.
- Configuration, Docker volume support, documentation, and tests.

### Not included in the first implementation

- Databricks integration.
- Multiple actively writing service replicas. SQLite is appropriate for a single service instance/POC, not the final horizontally scaled JANUS deployment.
- Asynchronous job processing or a `running` API workflow.
- Storing model credentials, HTTP authorization headers, or raw environment values.
- Changing the current terminal-state semantics.
- Removing `structured_result` from `POST /invoke`; that should be a later, versioned contract change.

## 4. Proposed Database Location and Configuration

Add the following non-secret setting:

```dotenv
DATABASE_PATH=./data/control_translation.db
```

Behavior:

- Local default: `./data/control_translation.db`.
- Tests: a separate temporary database per test or test fixture.
- Container: `/app/data/control_translation.db` backed by a mounted volume.
- Parent directories are created during startup when they do not exist.
- `data/`, `*.db`, `*.db-shm`, and `*.db-wal` are ignored by Git.
- The readiness endpoint verifies that the database can be opened and queried.

Recommended SQLite connection settings:

- `PRAGMA foreign_keys = ON`
- `PRAGMA journal_mode = DELETE` for the durable single-replica mounted volume
- `PRAGMA busy_timeout = 5000`
- `PRAGMA synchronous = NORMAL`

Each repository operation should open its own short-lived connection. Connections must not be shared globally across FastAPI request threads.

## 5. Proposed Schema

SQLite stores authoritative JSON snapshots while selected columns are normalized for reliable lookup, filtering, integrity checks, and future migration.

### 5.1 `schema_migrations`

Tracks database schema versions without requiring a third-party migration dependency.

| Column | Type | Constraints | Purpose |
|---|---|---|---|
| `version` | INTEGER | PRIMARY KEY | Applied migration number. |
| `name` | TEXT | NOT NULL | Human-readable migration name. |
| `applied_at` | TEXT | NOT NULL | UTC ISO-8601 timestamp. |

Initial migration: `1 / initial_persistence_schema`.

### 5.2 `capability_runs`

One row per capability execution. This is the primary durable run record.

| Column | Type | Constraints | Purpose |
|---|---|---|---|
| `run_id` | TEXT | PRIMARY KEY | Execution identifier returned by the API. |
| `capability` | TEXT | NOT NULL | Normally `control-translation`. |
| `contract_id` | TEXT | NOT NULL | Result contract version, currently `control-translation@1.0`. |
| `request_id` | TEXT | NULL | Existing caller request ID. |
| `correlation_id` | TEXT | NOT NULL | JANUS-wide correlation identifier. |
| `idempotency_key` | TEXT | NULL | Reserved for retry-safe invocation behavior. |
| `request_hash` | TEXT | NOT NULL | SHA-256 of canonical request JSON. |
| `result_id` | TEXT | NOT NULL | Durable business-result identifier. |
| `status` | TEXT | NOT NULL | Existing envelope status. |
| `terminal_state` | TEXT | NOT NULL | Documented business terminal state. |
| `outcome_reason_code` | TEXT | NOT NULL | Typed result reason code. |
| `started_at` | TEXT | NOT NULL | UTC execution start time. |
| `completed_at` | TEXT | NOT NULL | UTC completion time. |
| `created_at` | TEXT | NOT NULL | UTC row creation time. |
| `updated_at` | TEXT | NOT NULL | UTC last update time. |

Indexes and constraints:

- Unique index on `result_id` after result IDs are made execution-unique.
- Non-unique indexes on `correlation_id`, `request_id`, `terminal_state`, and `completed_at`.
- Partial unique index on `idempotency_key` where it is not null.
- Check constraints for known status and terminal-state values where practical.

Important prerequisite: the current result ID ends in a hard-coded `:1` and can collide across repeated invocations. Before enforcing uniqueness, result generation must use a UUID/ULID suffix or a defined versioning/idempotency rule.

### 5.3 `invocation_payloads`

Stores immutable request and final response snapshots separately from searchable run metadata.

| Column | Type | Constraints | Purpose |
|---|---|---|---|
| `run_id` | TEXT | PRIMARY KEY, FK | References `capability_runs(run_id)` with cascade delete. |
| `request_json` | TEXT | NOT NULL | Complete validated `InvokeRequestEnvelope`. |
| `result_json` | TEXT | NOT NULL | Complete final `ResultEnvelope`, including `structured_result`. |
| `prose_summary` | TEXT | NOT NULL | Final human-readable summary. |
| `inference_json` | TEXT | NOT NULL | Safe inference metadata already exposed by the API. |
| `warnings_json` | TEXT | NOT NULL | Warning list. |
| `trace_json` | TEXT | NOT NULL | Capability trace list. |

JSON serialization rules:

- Use Pydantic `model_dump_json()` or canonical `json.dumps(..., sort_keys=True, separators=(",", ":"))`.
- Persist only validated models.
- Preserve UTC timestamps in ISO-8601 format.
- Never persist settings objects, API keys, authorization headers, or provider endpoints unless explicitly approved.

### 5.4 `result_artifacts`

Stores generated candidate artifacts separately so they can later be moved to object storage or Databricks without rewriting run metadata.

| Column | Type | Constraints | Purpose |
|---|---|---|---|
| `artifact_id` | TEXT | PRIMARY KEY | Candidate ID or generated artifact identifier. |
| `run_id` | TEXT | NOT NULL, FK | Owning execution. |
| `result_id` | TEXT | NOT NULL | Owning business result. |
| `artifact_type` | TEXT | NOT NULL | Akamai WAF rule, firewall rule, EDR rule, etc. |
| `content` | TEXT | NOT NULL | Generated candidate content currently held in `content_ref`. |
| `content_hash` | TEXT | NOT NULL | Existing artifact hash. |
| `emitted_as` | TEXT | NOT NULL | Artifact classification. |
| `created_at` | TEXT | NOT NULL | UTC creation time. |

Indexes: `run_id`, `result_id`, and `content_hash`.

The first implementation will retain artifact content inside `result_json` for response compatibility and also persist it here. A later contract version should replace inline content with a durable artifact reference.

### 5.5 `evidence_references`

Stores references, not external evidence bodies.

| Column | Type | Constraints | Purpose |
|---|---|---|---|
| `id` | INTEGER | PRIMARY KEY AUTOINCREMENT | Internal row ID. |
| `run_id` | TEXT | NOT NULL, FK | Owning execution. |
| `result_id` | TEXT | NOT NULL | Owning business result. |
| `claim` | TEXT | NOT NULL | Evidence claim or `provenance`. |
| `evidence_ref` | TEXT | NOT NULL | External evidence/proof reference. |
| `created_at` | TEXT | NOT NULL | UTC creation time. |

A uniqueness constraint on `(run_id, claim, evidence_ref)` prevents duplicate bindings.

## 6. Application Design

Create a persistence package:

```text
src/control_translation/persistence/
    __init__.py
    base.py
    sqlite.py
    migrations.py
```

### `base.py`

Define a small repository protocol, for example:

- `initialize()`
- `healthcheck()`
- `save_completed_run(request_envelope, result_envelope, started_at)`
- `get_run(run_id)`
- `get_result(result_id)`
- `get_by_idempotency_key(idempotency_key)`

The capability's translation/domain logic must not contain SQL.

### `sqlite.py`

Implement the repository using parameterized SQL only. Responsibilities:

- connection creation and PRAGMA configuration;
- migration execution;
- transaction handling;
- Pydantic serialization/deserialization;
- artifact and evidence extraction;
- conversion of database corruption or write failures into typed persistence errors.

### `migrations.py`

Contain ordered, immutable migration definitions. Startup applies missing migrations inside transactions. Never silently delete or recreate an existing database.

## 7. Invocation and Transaction Flow

The compatibility-preserving first phase will use this flow:

1. FastAPI validates `InvokeRequestEnvelope`.
2. API establishes `request_id` and `correlation_id`.
3. Capability executes exactly as it does today.
4. The final `ResultEnvelope` receives durable reference metadata.
5. Repository starts one SQLite transaction.
6. Insert `capability_runs`.
7. Insert `invocation_payloads` with the complete validated request and final output.
8. Insert candidate artifact when present.
9. Insert all evidence/provenance references.
10. Commit the complete transaction.
11. Return the unchanged-compatible response to the caller.

If any persistence step fails, the transaction rolls back. The API must not claim a durable successful completion when its final result could not be persisted. Return a controlled HTTP `503` or typed malfunction response according to the final JANUS API decision; do not silently fall back to memory.

## 8. API and Contract Changes

### Phase 1: backward-compatible

- Keep `POST /invoke` and its existing `ResultEnvelope` response.
- Keep `GET /runs/{run_id}`, but load from SQLite.
- Add optional `correlation_id` and `idempotency_key` fields to `InvokeRequestEnvelope`.
- Add `result_id`, `correlation_id`, and `result_ref` to `ResultEnvelope` as additive fields.
- Add `GET /v1/results/{result_id}` returning the persisted full `ControlTranslationResult` or a documented result envelope.
- Add a bounded `GET /v1/runs` metadata projection for operational UI use.
   The implemented endpoint uses `limit`/`offset`, newest-first ordering, and
   excludes stored request JSON and candidate artifact content.
- Set `result_ref` to a service-level stable reference, not an absolute local filesystem path. Example:

```json
{
  "system": "control-translation",
  "type": "result-api",
  "result_id": "control-translation-result:<unique-id>",
  "href": "/v1/results/control-translation-result:<unique-id>"
}
```

Do not expose `DATABASE_PATH` or SQLite table names as the public JANUS contract.

### Phase 2: versioned compact completion contract

After downstream consumers and the UI are updated, add a versioned endpoint/response that returns only the JANUS completion envelope. Retrieve the large final result and candidate artifact through the result API. Do not remove fields from the existing endpoint without a versioned migration.

## 9. Idempotency and Identifier Rules

Before adding the unique result index:

1. Change `result_id` generation from the current deterministic `...:1` suffix to a collision-safe UUID/ULID, unless JANUS defines a canonical result-version rule.
2. Generate `run_id` once before capability execution and carry it through persistence and response assembly.
3. Accept an optional caller `idempotency_key`.
4. Hash canonical validated input.
5. If an existing idempotency key has the same request hash, return the already persisted result.
6. If the same idempotency key is reused with a different hash, return HTTP `409 Conflict`.
7. Preserve the caller's correlation ID; generate one when absent.

This behavior must be specified and tested before production use.

## 10. Startup, Readiness, and Shutdown

- Initialize migrations during FastAPI lifespan startup rather than module import.
- Fail startup when schema initialization fails.
- `/health` remains process liveness only.
- `/ready` checks both existing configuration and a lightweight database query such as `SELECT 1`.
- Do not keep a mutable global SQLite connection.
- The database file must not be served by the static file mount.

## 11. Docker and Local Development

Update `docker-compose.yml` with a persistent named volume:

```text
/app/data
```

Add `DATABASE_PATH=/app/data/control_translation.db` to the service environment. Document that:

- deleting the container does not delete the named volume;
- `docker compose down -v` intentionally deletes local database data;
- SQLite deployments remain single-replica;
- future multi-replica deployment requires a shared database/system of record.

## 12. Test Plan

### Unit tests

- Schema initializes on an empty database.
- Re-running initialization is safe.
- All migrations are recorded exactly once.
- A completed translated result round-trips without field loss.
- Every non-success terminal state round-trips.
- Candidate artifacts and evidence references are persisted.
- Requests and full final envelopes are stored.
- No secret configuration fields are stored.
- Duplicate idempotency key with the same request returns the existing result.
- Duplicate idempotency key with different input is rejected.
- Concurrent writes within the supported single-process model honor busy timeout and do not corrupt data.
- A failed child insert rolls back the entire run transaction.

### API tests

- Existing health, schema, inference, invocation, terminal-state, and adapter tests continue to pass unchanged where possible.
- `POST /invoke` persists before returning success.
- `GET /runs/{run_id}` succeeds after clearing process state/recreating the app.
- `GET /v1/results/{result_id}` returns the persisted final result.
- Missing run/result returns `404`.
- Correlation ID is accepted and returned.
- Generated correlation ID is stable in the persisted record and response.
- Persistence failure produces a controlled response and no false success.
- `/ready` returns `503` when the database is unavailable.

### Restart integration test

1. Invoke the capability using a temporary on-disk SQLite database.
2. Dispose and recreate the application/repository.
3. Retrieve by both `run_id` and `result_id`.
4. Assert exact validated-model equivalence.

### Regression gate

Run the complete existing test suite before and after each phase. No persistence change is complete until all existing terminal-state, fixture-mode, API, schema, and adapter tests pass.

## 13. Implementation Sequence

1. **Configuration and safety**
   - Add `DATABASE_PATH` to `Settings` and `.env.example`.
   - Add database files/directories to `.gitignore` and `.dockerignore` if needed.
   - Add temporary-database test fixtures.

2. **Persistence foundation**
   - Add repository protocol, SQLite implementation, errors, and migrations.
   - Add schema and round-trip unit tests.

3. **Identifiers and additive contracts**
   - Add correlation/idempotency fields.
   - Make result IDs collision-safe.
   - Add `result_id` and `result_ref` to the outer envelope without removing existing fields.
   - Regenerate JSON schemas and update examples.

4. **API integration**
   - Replace `_RUNS` writes and reads with repository operations.
   - Initialize the repository through FastAPI lifespan.
   - Add database readiness check.
   - Add result lookup endpoint.

5. **Container persistence**
   - Add the Docker Compose volume and database environment configuration.
   - Update deployment guidance to require one replica for SQLite.

6. **Validation and documentation**
   - Run the full test suite.
   - Regenerate request/result schemas with `scripts/generate_schemas.py`.
   - Update README endpoint, configuration, storage, backup, and limitation sections.
   - Confirm UI/API compatibility manually.

## 14. Data Safety and Operations

- Database file permissions should restrict access to the service identity.
- Do not include the database in the container image.
- Do not commit local database files.
- Candidate artifacts and policy-related input may be sensitive; apply approved disk/volume encryption and backup controls.
- Define retention before production use. Initial POC behavior may retain records indefinitely, but this must be explicit.
- Add a documented backup procedure using SQLite's backup API or an approved volume snapshot; copying a live WAL database file directly is not a reliable backup strategy.
- Redact sensitive payloads from logs even though they are intentionally persisted in the approved data store.

## 15. Acceptance Criteria

The SQLite persistence work is complete when:

- Every successful or declined invocation is durably stored before its response is returned.
- The complete validated request and final `ResultEnvelope` can be reconstructed after restart.
- Candidate content and evidence references are queryable by run/result identifiers.
- `GET /runs/{run_id}` no longer depends on `_RUNS`.
- A durable result endpoint works by `result_id`.
- Responses include stable correlation and result-reference information.
- Database failures do not produce false successful completion responses.
- Existing API behavior and all current tests remain valid unless an intentional additive contract change is documented.
- Database files and secrets cannot be committed accidentally.
- Docker Compose preserves the database through ordinary container recreation.
- The README clearly states that SQLite is a single-instance POC persistence layer and not the final JANUS system of record.

## 16. Remaining Production Decisions

Confirm these items with the JANUS/platform owner:

1. Confirm that the implemented `correlation_id` and `idempotency_key` names
   match the final JANUS standard contract.
2. Decide whether malformed/validation-rejected HTTP requests must also be
   persisted. Phase 1 stores validated capability invocations only.
3. Define classification, encryption, retention, and deletion policy for
   generated candidate content and model metadata.
4. Confirm whether a persistence failure remains HTTP `503` or becomes a
   versioned `malfunction` completion envelope.
5. Decide whether the full result endpoint requires additional authorization
   or candidate-content redaction.
6. Confirm the implemented collision-safe result ID format, which appends a
   UUID to the vulnerability and target technology.
