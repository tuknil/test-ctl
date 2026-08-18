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
   HTTP client   │   FastAPI api.py    │   static UI (ui/) served at "/"
  ───────────►   │  /health /schema    │
                 │  /invoke /runs/{id} │
                 └─────────┬───────────┘
                           │
                 ┌─────────▼───────────┐
                 │   capability.py     │  orchestration + terminal routing
                 └───┬─────────────┬───┘
                     │             │
        ┌────────────▼──┐   ┌──────▼─────────────┐
        │ policy_reader  │   │ translation/engine  │
        │ (fixture only) │   │  ├─ adapters/*      │
        └────────────────┘   │  ├─ agents/         │
                              │  │  translation_agent│  (doer)
                              │  ├─ syntax_validator │  (judge)
                              │  └─ conflict_checker │  (judge)
                              └─────────────────────┘
```

## 3. Data models

See `src/control_translation/contracts.py` for the full Pydantic model set:
`ProvenMitigationPattern`, `TargetContext`, `TranslationPolicy`,
`ControlTranslationRequest`, `ControlTranslationResult` and its
substructures (`Subject`, `InputBindings`, `OutcomeReason`,
`PrimaryCandidate`, `CandidateArtifact`, `ImplementsDiscriminator`,
`Placement`, `CollateralImpactPrior`, `EvidenceBinding`), plus the API
envelope models `InvokeRequestEnvelope` / `ResultEnvelope`. Terminal states
and reason codes live in `terminal.py`.

## 4. Sequence (happy path)

1. `POST /invoke` → `capability.invoke_envelope` → `capability.invoke`.
2. Resolve `TargetAdapter` from registry; unknown target → `scope-declined`.
3. If no `current_policy_snapshot_id` supplied, call `PolicyReader.read_snapshot`;
   miss → `insufficient-context`.
4. `translation/engine.translate`:
   a. `adapter.supports_feature(discriminator_description)` mechanical pre-check;
      fails → `cannot-express`.
   b. Call the doer (`FixtureTranslationDoer` or `LiveTranslationDoer`) →
      `TranslationProposal`; exception → `malfunction` (`provider-failure`).
   c. `syntax_validator.validate` (judge gate 1); fails → `cannot-express`.
   d. `conflict_checker.detect_conflicts` (judge gate 2); non-empty → surfaced
      as `conflict_notes`.
5. Back in `capability.invoke`: if conflicts present → `scope-declined`
   (`policy-conflict`); else assemble `translated` result.
6. `capability._envelope` wraps the result in `ResultEnvelope`
   (status/run_id/prose/trace) and `api.py` stores it in the in-memory
   `_RUNS` map keyed by `run_id`.

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
| Proven pattern source | `providers/fixtures.py`, 3 canned patterns | Caller supplies real pattern via request body (upstream capabilities not yet built) |
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

## 9. Persistence design

In-memory dict (`api._RUNS`) keyed by `run_id`. Lost on process restart.
Swap point: replace with a real store (Redis/Postgres/etc.) behind the same
`get_run(run_id) -> ResultEnvelope | None` shape used in `api.py`.

## 10. Agent architecture

- Doer: `agents/translation_agent.py`. `TranslationProposal` is the only
  trusted output shape from the model.
- Model/provider config: `config.py::Settings`, sourced from `.env`
  (`RUN_MODE`, `MODEL_PROVIDER`, `MODEL_NAME`, `OPENAI_API_KEY` or Azure
  OpenAI equivalents). `RUN_MODE=fixture` is the default and requires no key.
- Judge: `translation/syntax_validator.py` + `translation/conflict_checker.py`,
  both purely deterministic, both delegate the target-specific check to the
  adapter.

## 11. Deployment architecture summary

Container needs: Python 3.11+ runtime, `uvicorn control_translation.api:app`
entrypoint, port 8000, static `ui/` directory alongside `src/`, `.env`
variables injected as container secrets (never baked into the image). Full
DevOps handoff spec: `deploy/DEVOPS-HANDOFF.html`. A working `Dockerfile`,
`.dockerignore`, and `docker-compose.yml` are included in this repo as a
starting point for DevOps to adapt.

## 12. Testing strategy

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

All default tests run offline with no network access or API key.

## 13. Assumptions & open questions

See `docs/assumptions-and-followups.md` for the full list.
