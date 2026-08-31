# Assumptions and follow-ups

## Explicit assumptions made in this build

- No live Akamai/Palo Alto/SentinelOne API access exists yet — all policy
  reads are **fixture-based approximations**. Target **rule syntax** is now
  sourced from documented real formats (see `docs/syntexresearch.md`:
  Akamai custom-rule JSON, PAN-OS security-rule CLI/XML, SentinelOne STAR
  JSON), but the generated artifacts are still **not validated against a
  real tenant**.
- Reference-based upstream integration is implemented. Control Translation
  reads exact result IDs from the live Defense Generation, Mitigation Check,
  and Bypass Validation Unity Catalog tables and validates cross-record
  correlation, subject revision, vulnerability, candidate, and route state.
  Legacy fixture patterns remain for deterministic tests and demonstrations.
- Databricks CLI access, warehouse availability, source-table schemas, and
  representative records were verified with a developer identity. The managed
  deployment's OAuth M2M identity and grants must still be validated in each
  environment.
- Conflict detection is simplistic (keyword/pattern overlap against a small
  fixture policy set), not a full policy-diff engine.
- No authentication/authorization on the API — acceptable for demo/POC,
  must be added before any real deployment carries sensitive policy data.
- Persistence is backend-selectable. SQLite provides atomic local durability
  for development/tests. The Databricks SQL implementation writes the existing
  Unity Catalog results table and is intended as the shared Azure backend, but
  still requires live grant/connectivity and operational validation.
- The Pydantic AI agent is a **doer** proposing candidate artifacts; a
  deterministic **judge** (`syntax_validator` + `conflict_checker`) gates
  the result before `translated` is ever emitted — no raw LLM text becomes
  a trusted fact.
- API key and model config are read from a local `.env` file via
  `python-dotenv` — never committed. `.env.example` documents variable
  names only. Default/offline tests use `FixtureTranslationDoer` and
  require no key or network access.
- Whether EDR/SentinelOne is even in MVP scope is unconfirmed; the
  `edr-s1` adapter now validates the SentinelOne STAR custom-rule JSON
  shape (`docs/syntexresearch.md`), so this is a **scope** question, not a
  feasibility one.

## Backlog — add once available/confirmed

- Real Akamai WAF policy-read API integration (owner: TBD — see Janus
  `artifacts/spikes.md` "live-policy" spike).
- Real Palo Alto / firewall policy-read + rule-syntax integration.
- Real SentinelOne/EDR policy model, once/if EDR is confirmed in scope.
- Validate Databricks OAuth M2M warehouse/catalog/schema/table grants,
  retention, query performance, and recovery in the target Azure environment.
- Add strong concurrent idempotency enforcement before increasing the service
  beyond one writer replica.
- AuthN/AuthZ + secrets management (e.g. Azure Key Vault) before handling
  real policy data.
- Richer multi-policy conflict analysis (CFS §8 deferred item).
- Multiple candidate translations per target (CFS §8 deferred item).
- A bounded retry/repair loop for agent output that fails a judge gate
  (not implemented in this release — failures route straight to a
  terminal state).
