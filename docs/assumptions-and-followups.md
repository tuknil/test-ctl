# Assumptions and follow-ups

## Explicit assumptions made in this build

- No live Akamai/Palo Alto/SentinelOne API access exists yet — all policy
  reads are **fixture-based approximations**. Target **rule syntax** is now
  sourced from documented real formats (see `docs/syntexresearch.md`:
  Akamai custom-rule JSON, PAN-OS security-rule CLI/XML, SentinelOne STAR
  JSON), but the generated artifacts are still **not validated against a
  real tenant**.
- Real proven-mitigation-pattern inputs from `defense-generation` /
  `mitigation-check` / `bypass-validation` do not exist yet — fixtures
  synthesize plausible proven patterns (e.g. the OGNL/Content-Type example
  from the CFS, plus a firewall and EDR variant).
- Conflict detection is simplistic (keyword/pattern overlap against a small
  fixture policy set), not a full policy-diff engine.
- No authentication/authorization on the API — acceptable for demo/POC,
  must be added before any real deployment carries sensitive policy data.
- Persistence is in-memory (`_RUNS` dict in `api.py`); results are lost on
  restart — acceptable for demo, flagged for follow-up.
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
- Replace fixture proven-mitigation-pattern samples with real outputs once
  `defense-generation` / `mitigation-check` / `bypass-validation` exist.
- Durable persistence (a real database) once this moves past demo stage.
- AuthN/AuthZ + secrets management (e.g. Azure Key Vault) before handling
  real policy data.
- Richer multi-policy conflict analysis (CFS §8 deferred item).
- Multiple candidate translations per target (CFS §8 deferred item).
- A bounded retry/repair loop for agent output that fails a judge gate
  (not implemented in this release — failures route straight to a
  terminal state).
