# Shared attack contracts v2

`control-translation@2.0` is an additive invocation contract. The retained
`control-translation@1.0` direct and exactly-three-upstream routes are
unchanged and remain the replay path for existing histories.

## Request

A v2 request contains:

- `shared_contract_version: "2.0"`
- `profile_id: "waf-standard@2"` for new joins. Legacy replay may retain
  `waf-standard@1`, but profile revisions cannot be mixed within one join.
- stable `request_id` and `correlation_id`
- exactly four unique authenticated immutable `upstream_inputs`, one each for
  Check Generation, Defense Generation, Mitigation Check, and Bypass
  Validation
- optional target context and caller provenance

Every locator includes contract and terminal identity, approved Databricks
coordinates, request/run/result/correlation identity, canonical byte digest,
byte length, and creation time. The request schema is
`schemas/request.schema.json`; FastAPI exposes the same union in OpenAPI.

## Pre-translation ordering

The capability fetches and authenticates all four records before target policy
resolution or translation. It then verifies the offline schema bundle, CG
content and semantics digests, source projection, complete member partition,
DG candidate bundle and artifact bytes, atomic application unit, exact DG
obligation mappings, complete MC cases and accounting, complete BV campaigns,
candidate attestation, and chain lineage.

A failed join raises a typed non-retryable verification error and does not
construct a translation plan or call a model. A verified join produces strict
boolean/count evidence in `pre_translation_verification` and exact
`CoverageAccounting` with zero unaccounted required work.

The synchronous API returns the exact verification code and detail with
`retryable: false`. The asynchronous lifecycle persists that same code and
detail as a permanent run failure; it does not collapse verification failures
into `translation_execution_failed`.

## Complete WAF translation

The WAF translator works all-or-nothing. It preserves every DG cooperating
artifact in source order, every unique carrier plus selector and component,
every regex and transformation list, every directive, and every required
obligation mapping. The complete deterministic proposal remains subject to the
existing adapter expressibility, target syntax, translation policy, semantic,
policy snapshot, and conflict gates.

Both live and fixture configurations report this path as deterministic code:
`llm_invoked` and `proposal_from_doer` are false, `proposal_source` is
`deterministic-shared-contract-v2`, and the inference record identifies the
versioned deterministic actor plus the exact four upstream result IDs. Model
configuration may exist, but no model is constructed or called for this path.

Each emitted `target_artifacts[].artifact_id` is stable for its DG source
artifact. Each required obligation appears exactly once in
`translation_mappings`; every listed target ID must identify an artifact
actually emitted in the same result. If any required item cannot map without
semantic loss, the terminal state is `cannot-express` and `target_artifacts`,
`translated_directives`, and `translation_mappings` are all empty.

## Persistence and retries

The immutable result persists all four source locators, profile and shared
contract versions, verification, accounting, translated directives, target
artifacts, and mappings. Canonical content is assembled first; SHA-256 and byte
length are computed last over the exact content that is written.

Asynchronous lifecycle state stores only the compact request locators. Before
external publication, the worker durably stages the exact result envelope,
canonical result, completion, timestamps, and identities. Recovery from a
prepared or publication-pending state republishes those staged bytes and does
not invoke translation or a model again.

`tests/fixtures/shared-attack-contracts-v2/manifest.json` closes the fixture
set over exact byte lengths and SHA-256 digests. The assembled integration
chain follows current producer shapes, including MC
`route_policy: shared-attack-contracts-v2` and BV domain-result lineage under
`input_bindings.shared_contract_locators`; BV completion-owned request,
correlation, status, and integrity metadata are not invented inside the domain
result.