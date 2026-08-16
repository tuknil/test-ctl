# CFS extraction — control-translation

Black-box contract extracted from `docs/cfs-source.md` (CFS v1.0), used to
drive this service's implementation.

## Job

Given a proven mitigation pattern and a target control technology/context,
produce a control-specific mitigation candidate in the target stack's
policy/rule/config language — or a grounded reason it cannot be produced.

## Inputs

| Input | Required | This service |
|---|---|---|
| Proven mitigation pattern | Yes | `ProvenMitigationPattern` (fixture samples in `providers/fixtures.py`; no real `defense-generation`/`mitigation-check`/`bypass-validation` upstream yet) |
| Target control context | Yes | `TargetContext` |
| Current policy/config snapshot | Required when translation depends on it | `PolicyReader` seam, fixture-backed only |
| Translation policy | Yes | `TranslationPolicy` (minimal dials: `allow_narrower_translation`, `allow_equivalent_translation`) |
| Reference/proof bundle | Yes | Carried via `proof_record_ids` on the proven pattern |

## Output

`ControlTranslationResult` — see `src/control_translation/contracts.py` for
the exact Pydantic shape, matching CFS §2.

## Terminal states (CFS §4)

- `translated` — one primary candidate produced, defensive meaning preserved.
- `cannot-express` — target technology/policy model cannot represent the pattern.
- `insufficient-context` — required context (policy snapshot, feature support) missing.
- `scope-declined` — valid target outside configured coverage, or unresolved policy conflict.
- `malfunction` — provider/tooling/result-assembly failure.

## Precedence (CFS §4 state rules)

1. `scope-declined` wins before translation for out-of-coverage targets.
2. `insufficient-context` wins over `cannot-express` when missing context could change expressibility.
3. `cannot-express` when the target adapter cannot plausibly support the discriminator.
4. `malfunction` only when no trustworthy domain result can be emitted.
5. `translated` otherwise.

Implemented in `src/control_translation/capability.py::invoke`.

## What this service does NOT do (CFS §7 boundary)

- Does not generate the mitigation pattern (defense-generation's job).
- Does not prove block/bypass behavior (mitigation-check / bypass-validation's job).
- Does not run defense-validation or no-harm testing.
- Does not decide production safety.
- Does not deploy, confirm-landed, or roll back.
- Does not decide rollout health.
- Does not emit final `un-immunizable` residual labels.

## Deferred (CFS §8) — not built in this pass

- Additional target technologies beyond Akamai WAF / generic firewall / EDR stub.
- Richer multi-policy conflict analysis.
- Multiple candidate translations per target.
- Learning from defense-validation/deployment outcomes.
