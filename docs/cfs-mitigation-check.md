# CFS — mitigation-check
**Version 1.0**

_Tests whether a candidate mitigation blocks the attack or discriminator it claims to block, producing a bounded block/pass verdict and feedback for revision when it fails._

> **Handoff note:** This CFS defines the capability's functional semantics, externally meaningful outcomes, trust invariants, scope, and boundary. The engineering and implementation owner derives and maintains the production interface and implementation needed to satisfy them. Implementation choices must preserve the meanings and guarantees defined here.

```text
CFS: mitigation-check
Given a candidate mitigation, its discriminator or attack sample, and access to a validation substrate, run a bounded block/pass test and emit whether the candidate blocked the tested behavior, failed to block it, could not be tested, was outside configured coverage, or malfunctioned.
```

### 0 · CONTEXT — problem and solution shape

**Problem.** A mitigation candidate is only an intention until something proves it blocks the behavior it was built to stop. The candidate may look reasonable, match a written discriminator, or come from a strong model, but none of that proves the control actually stops the attack path. Without a separate block/pass oracle, defense generation can keep revising from vague feedback and downstream validation can inherit untested artifacts.

**Solution shape.** Mitigation-check receives one candidate mitigation, a test basis, and a validation substrate. It applies or uses the candidate in that substrate, sends the attack or discriminator sample through the relevant path, observes whether the behavior was blocked or allowed through, and emits a structured verdict. When the candidate fails to block, it emits typed feedback that defense-generation can use without knowing mitigation-check internals.

### 1 · CUSTOMER & JOB

- **Customer:** security engineers and orchestration running the fast mitigation proof loop or validating a candidate in a controlled environment.
- **Security question:** did this candidate mitigation block the specific attack or discriminator behavior it was asked to block in the selected validation substrate?
- **Job:** produce a block/pass verdict with enough evidence and feedback to either continue the proof loop, revise the candidate, or route a testing gap.
- **Safe action:** treat `blocked` as evidence that the candidate stopped the tested behavior under the stated proof basis and substrate; treat `not-blocked` as feedback for candidate revision; treat `could-not-test` as a substrate/evidence gap.
- **Prohibited inference:** the result does not prove bypass resistance, benign/no-harm behavior, production safety, deployability, fleet coverage, or that the tested discriminator is the actual vulnerability behavior when the proof basis is indirect.

### 2 · INVOKE CONTRACT — semantic shapes, not producers

#### Input

The capability accepts semantic inputs. Engineering owns concrete APIs and storage representations while preserving these meanings.

| Input | Meaning and requiredness |
|---|---|
| **Candidate mitigation** | **Required.** Stable identity and artifact reference for the candidate under test, including candidate kind, selected control class, discriminator/block condition, expected block behavior, assumptions, limitations, collateral-impact prior when available, and provenance. The candidate may be a fast-loop pattern/artifact or a control-specific candidate, depending on the workflow. |
| **Test basis** | **Required.** The attack or discriminator sample to send through the substrate, plus the expected blocked and not-blocked observations. The basis is either a verified proof-of-vulnerability artifact/attack sample or the mitigation's own discriminator. |
| **Validation substrate access** | **Required guarantee, not a producer-shaped input.** The runtime can apply or host the candidate mitigation, execute the test sample through the relevant path, and capture observations needed to decide blocked/not-blocked/unobservable. The substrate may be a local harness, Docker, iptables/mod_waf environment, dev control stack, SafeBreach-driven lab, vendor sandbox, or another bounded runner. |
| **Check profile** | **Required.** Configured coverage for supported candidate kinds, test-basis kinds, runner modalities, allowed observation points, timeout/resource bounds, retained-artifact policy, and attribution requirements for block evidence. A valid request outside this coverage yields `scope-declined`; the result must name the unsupported dimension such as candidate kind, test-basis kind, runner modality, or observation point. |

#### Proof basis semantics

Mitigation-check has two proof-strength levels:

| Proof basis | Meaning | Claim strength |
|---|---|---|
| `verified-vuln-artifact` | The test sample comes from a verified check/proof-of-vulnerability artifact or attack sample. | **Direct.** The candidate blocked behavior already proven to represent the vulnerability under check-generation's contract. |
| `mitigation-discriminator` | The test sample is derived from the candidate mitigation's discriminator/block condition. | **Indirect.** The candidate blocked what it claims to block; this does not prove the discriminator is the actual vulnerability behavior. |

Both are useful. The result must always state which basis was used. Absence of a verified check does not block mitigation-check; it lowers the claim strength to the discriminator path.

#### Block/pass semantics

A **blocked** result means the validation substrate observed the control stop the supplied sample according to the declared expected block behavior. A **not-blocked** result means the substrate observed the sample pass through or reach the protected behavior that should have been stopped. An **unobservable** result means the substrate could not determine either state.

The observation contract must be declared before execution. Examples:

- HTTP/WAF path: blocked may mean explicit block status, rule hit, connection termination, or absence of protected-service receipt with confirming control evidence.
- Firewall path: blocked may mean packet drop/reject observed at the control or absence at the protected receiver with confirming control evidence.
- Local harness path: blocked may mean process/handler did not receive the malicious input and the control action is attributable.

A timeout alone is not automatically blocked. A `blocked` result involving timeout or non-receipt requires explicit control-action evidence, such as a rule-hit/block log, explicit block status, packet drop/reject observation, candidate-attributable local guard decision, or another observation admitted by the check profile for that control class. Timeout without admitted control-action evidence is `could-not-test` unless a runtime failure prevents a valid result and produces `malfunction`.

#### Output

The capability emits a **Mitigation Check Result** with:

- `contract_id: mitigation-check@1.0`;
- candidate mitigation identity and artifact reference;
- test basis identity and proof strength;
- validation substrate/run identity;
- one terminal state and non-blank outcome reason;
- block/pass observations and evidence;
- feedback package when the result is `not-blocked`;
- evidence/provenance bindings, limitations, gaps, and explicit unknowns; and
- a human-readable prose explanation derived from structured fields.

Illustrative semantic result shape:

```yaml
MitigationCheckResult:
  contract_id: mitigation-check@1.0
  result_id: mitigation-check-result:CVE-EXAMPLE:candidate-3:1
  produced_at: 2026-08-11T00:00:00Z
  subject:
    vulnerability_id: CVE-EXAMPLE
    candidate_id: candidate:CVE-EXAMPLE:waf:attempt-3
    candidate_fingerprint_id: candidate-fingerprint:CVE-EXAMPLE:waf:attempt-3
  input_bindings:
    candidate_artifact_id: candidate:CVE-EXAMPLE:waf:attempt-3
    test_basis_id: test-basis:CVE-EXAMPLE:cmd-metacharacters
    proof_basis: verified-vuln-artifact | mitigation-discriminator
    proof_strength: direct | indirect
    validation_substrate_id: substrate:local-waf-harness:run-7
    check_profile_id: mitigation-check-profile:mvp1
    unsupported_dimension: candidate-kind | test-basis-kind | runner-modality | observation-point | none
  terminal_state: blocked | not-blocked | could-not-test | scope-declined | malfunction
  outcome_reason:
    code: blocked | not-blocked | observation-unavailable | unsupported-candidate-kind |
      unsupported-test-basis | runner-unavailable | invalid-input | result-assembly-failure
    detail: non-blank explanation
  observations:
    sample_sent:
      sample_ref: evidence://samples/cmd-metacharacters
      expected_block_behavior: non-blank
    control_observation:
      observed: blocked | not-blocked | unobservable
      evidence_refs: []
    protected_target_observation:
      observed: reached | not-reached | unobservable
      evidence_refs: []
  feedback:
    feedback_id: mitigation-feedback:attempt-3:block
    source: mitigation-check
    rejected_candidate_id: candidate:CVE-EXAMPLE:waf:attempt-3
    failed_gate: block
    observed_failure: non-blank when terminal_state is not-blocked
    why_it_sucks: non-blank explanation of the candidate weakness when reusable
    do_not_repeat: non-blank description of the design mistake to avoid when reusable
    counterexample:
      kind: attack-sample | discriminator-sample | none
      reference: evidence://samples/cmd-metacharacters
    evidence_refs: []
    reusable: true | false
    reusable_reason: non-blank
  limitations: []
  prose_summary: non-blank human explanation
```

This is a semantic shape, not a mandated wire format.

#### Invocation and affordances

- **keyed on →** candidate mitigation identity × test basis identity × validation substrate/run identity × check profile identity.
- **invocation →** asynchronous job. Substrate setup, candidate application, sample execution, and observation capture are not instant.
- **affords →** `blocked` supplies block evidence and proof strength for workflow routing, including possible bypass-validation or later validation. `not-blocked` provides typed feedback for defense-generation. `could-not-test` routes to substrate/evidence repair. No result is a production-safety or deployment decision.

### 3 · METHOD INVARIANTS — what makes the result trustworthy

- **Must bind to one candidate and one test basis.** The result cannot aggregate several candidates or several unrelated samples into one verdict unless a later contract version defines that aggregation.
- **Must state proof basis and strength.** Direct and indirect proof claims are different and must not be collapsed.
- **Must use the validation substrate as the execution boundary.** The capability runs the sample only through the supplied substrate/runner and never against production or arbitrary live targets.
- **Must observe block/pass mechanically before interpretation.** The block/pass verdict is grounded in substrate observations, not model confidence or candidate prose.
- **Must not treat timeout or absence as block without attribution.** Blocked requires evidence that the mitigation/control caused the stop. Timeout or protected-target non-receipt requires at least one admitted control-action observation, such as explicit block status, rule hit, packet drop/reject, or candidate-attributable local guard decision. Timeout-only evidence yields `could-not-test` unless a runtime defect produces `malfunction`.
- **Must emit feedback on `not-blocked`.** Failed block checks produce a typed feedback package with observed failure, counterexample, `why_it_sucks`, `do_not_repeat` when reusable, `reusable`, `reusable_reason`, and evidence references.
- **Must define feedback reusability.** `reusable: true` means the failure explains a real candidate weakness that defense-generation should avoid repeating in the current loop. It requires the finding to apply to the same selected control class, discriminator or candidate-fingerprint dimension, test basis, and check-profile scope with concrete evidence. `reusable: false` preserves the evidence but does not require defense-generation to carry it forward as a do-not-repeat lesson.
- **Must distinguish untestable from not-blocked.** If the substrate lacks the needed observation point or cannot apply the candidate, emit `could-not-test` or `scope-declined`; do not report `not-blocked` merely because proof could not run.
- **Must decline unsupported coverage explicitly before execution.** A valid candidate kind, test-basis kind, runner modality, or observation point outside configured coverage yields `scope-declined`, not `not-blocked` or `malfunction`, and the result names the unsupported dimension. Once candidate application or sample execution starts, later substrate/evidence failure yields `could-not-test` or `malfunction`, not `scope-declined`.
- **Must not claim bypass resistance or no-harm.** Blocking one sample does not mean variants are blocked or benign traffic is safe. Downstream preservation or gating of `proof_strength` is outside this capability; this capability's obligation is to emit it accurately on every result.
- **Must not emit coverage-facts or residual labels.** This capability emits proof evidence and feedback only.
- **Must keep prose non-authoritative.** Structured fields are the contract; prose explains them.

### 4 · EMIT & PERSIST — results and terminal states

#### Persist and emit

Persist valid results by stable result identity. Persist substrate run identity, candidate artifact reference, test sample reference, observations, control-action attribution evidence, proof basis, proof strength, feedback package, limitations, and evidence bindings. Emit safe observable exhaust: substrate setup summary, sample execution trace, control observations, protected target observations, and runner/provider failures. Do not persist secrets or unredacted sensitive payloads outside policy.

Structured fields are authoritative. The prose summary is display-only and must not introduce conclusions absent from structured fields.

#### Terminal-state field matrix

| Terminal state | Assertion | Observation record | Feedback | Safe action | Must not infer | Escalation |
|---|---|---|---|---|---|---|
| `blocked` | Candidate mitigation blocked the supplied sample under the stated proof basis and substrate, with candidate-attributable control-action evidence. | **Required**, with control/protected-target evidence and explicit attribution when timeout or non-receipt is part of the claim. | Optional. | Use as block evidence for workflow routing under the stated proof basis. | Bypass resistance, no-harm, production safety, deployment success, or that indirect basis proves the real vuln. | No human required solely for block proof. |
| `not-blocked` | Candidate mitigation failed to block the supplied sample; the sample reached or triggered behavior it should have stopped. | **Required.** | **Required** feedback package. | Return feedback to defense-generation. | The control class can never work; all future candidates will fail. | No human required unless policy asks for review. |
| `could-not-test` | The capability could not reach a trustworthy block/pass verdict because required substrate, candidate application, sample execution, or observation was unavailable. | Required when partial execution occurred. | Optional diagnostic feedback only. | Repair substrate/evidence/context and retry. | Candidate blocked or failed to block. | Route to substrate/evidence owner. |
| `scope-declined` | Before execution starts, input is valid but candidate kind, test basis, runner modality, or observation point is outside configured coverage. The unsupported dimension is named. | Absent. | Absent. | Use supported configuration or capability version. | Candidate failed; substrate broke. | No retry until coverage/config changes. |
| `malfunction` | A valid domain result could not be emitted because input parsing, runner/tooling, persistence, or result assembly failed. | Optional partial diagnostics only. | Absent as trusted feedback. | Repair and retry or escalate to capability/runtime owner. | Any domain conclusion about block/pass. | Human/retry required. |

#### State rules

- `blocked` requires a declared expected block behavior and substrate evidence that the candidate caused the block, including admitted control-action attribution when timeout or non-receipt supports the claim.
- `not-blocked` requires evidence that the sample was not blocked and reached or triggered the relevant protected path.
- `could-not-test` wins when missing substrate/observation context could change the block/pass conclusion after the request is in coverage or execution has started.
- `scope-declined` wins only before execution starts for valid requests outside configured coverage, and the result names the unsupported dimension.
- Once candidate application or sample execution starts, valid non-positive outcomes are `could-not-test` or `malfunction`, not `scope-declined`.
- `malfunction` wins only when no trustworthy domain result can be emitted.
- `blocked` with `proof_strength: indirect` must state that it proves only the mitigation discriminator was blocked.

### 5 · ACCEPTANCE CRITERIA — prove the contract

**Done =** a customer can use the result to know whether one candidate blocked one supplied sample in one validation substrate, and can route failure/untestable outcomes without inventing missing proof meaning.

#### Invariant-to-check mapping

| Invariant | Observable check |
|---|---|
| One candidate / one basis | Result identity and subject bind exactly one candidate and one test basis. |
| Proof basis explicit | Every result states `verified-vuln-artifact` or `mitigation-discriminator` and direct/indirect strength. |
| Substrate boundary | Invocation cannot use arbitrary production target coordinates as the test path. |
| Mechanical observation | `blocked` and `not-blocked` results cite substrate observations. |
| Timeout attribution | Timeout or non-receipt cannot produce `blocked` without admitted control-action evidence such as explicit block status, rule hit, packet drop/reject, or candidate-attributable local guard decision. |
| Feedback on failure | `not-blocked` includes feedback with counterexample or failure evidence, `why_it_sucks`, `do_not_repeat` when reusable, and `reusable_reason`. |
| Untestable distinction | Missing observation point yields `could-not-test`, not `not-blocked`. |
| Scope explicit | Unsupported runner/test basis yields `scope-declined` before execution and names the unsupported dimension. |
| Partial execution routing | Substrate or observation failure after candidate application or sample execution yields `could-not-test` or `malfunction`, not `scope-declined`. |
| Boundary preserved | No result claims bypass resistance, no-harm, prod-safe, deployment, rollout health, or coverage-fact. |
| Prose non-authority | Removing prose does not remove any domain conclusion. |

#### Conformance scenarios

| Scenario | Expected terminal outcome | Security meaning | Must not happen |
|---|---|---|---|
| Candidate WAF pattern blocks the verified check-generation attack sample in the local WAF harness and the WAF emits an explicit block decision tied to the candidate | `blocked` with direct proof strength | The candidate blocked verified vulnerability behavior in that substrate. | Claim bypass resistance or production safety. |
| Candidate blocks a discriminator sample derived from its own rule condition; no verified check exists | `blocked` with indirect proof strength | The candidate blocks what it claims to block. | Claim the discriminator is proven to be the actual vuln behavior. |
| Attack sample reaches the protected handler despite candidate being applied | `not-blocked` | Candidate failed the block gate. | Route as `could-not-test` or no-defense without feedback. |
| Substrate cannot expose whether the protected handler received the sample | `could-not-test` | Block/pass is unknown because observation is unavailable. | Treat absence of evidence as blocked. |
| Candidate kind is valid but unsupported by this mitigation-check profile | `scope-declined` | This request is outside configured coverage. | Emit `not-blocked` or `malfunction`. |
| Runner crashes before trustworthy observations are captured | `malfunction` | No domain verdict exists. | Emit diagnostic feedback as if it were block failure. |
| Sample times out and the control log is unavailable | `could-not-test` | The result cannot attribute timeout to the mitigation. | Report `blocked`. |
| Sample times out and the WAF emits an explicit candidate rule-hit/block decision for that request | `blocked` if all other evidence is valid | Timeout is attributable to the candidate's control action under the profile. | Report `blocked` from timeout alone. |
| Candidate kind is in coverage and sample execution starts, but the substrate loses the protected-target observation mid-run | `could-not-test` | Execution began, but block/pass cannot be trusted. | Reclassify as `scope-declined`. |
| Candidate kind is unsupported by the profile before execution begins | `scope-declined` with unsupported dimension `candidate-kind` | Request is valid but outside configured coverage. | Emit `could-not-test` or omit the unsupported dimension. |
| Failure shows the rule did not cover URL-decoded input and applies to the same discriminator/profile scope | `not-blocked` with `reusable: true` | Defense-generation should avoid repeating the same design mistake. | Emit feedback with no reason why the candidate failed. |
| Failure was caused by stale substrate setup rather than candidate design | `could-not-test` or `malfunction` depending whether a valid result can be emitted | The evidence should not become a reusable design lesson. | Mark reusable and force defense-generation to redesign around lab failure. |

### 6 · GUARANTEES DEPENDED ON — the “we do not care how” boundary

- **Validation substrate / isolated runner.** The runtime can apply or host the candidate mitigation, send the test sample through the relevant path, bind execution to the supplied candidate/substrate, enforce time/resource limits, and capture control/protected-target observations or a typed unavailable result. [integrate]
- **Candidate and test-basis access.** The runtime supplies candidate mitigation artifact, discriminator, expected block behavior, and test sample with stable identity and provenance. [provided]
- **Observation capture.** The substrate can capture enough evidence to distinguish blocked, not-blocked, and unobservable for supported runner modalities, including admitted control-action attribution evidence when timeout or protected-target non-receipt supports a block claim. [provided]
- **Artifact/result persistence.** Results, observations, control-action attribution evidence, feedback packages, substrate run IDs, and evidence references can be persisted with stable identity. [provided]
- **Secret and sensitive-data controls.** Candidate artifacts, samples, substrate logs, and traces are stored or redacted according to policy; secrets are not emitted in results. [provided]

### 7 · BOUNDARY — not this capability, ever

- **Generating or revising mitigations.** Defense-generation creates candidates; this capability tests them.
- **Bypass search.** It does not mutate attacks or search for evasions; bypass-validation owns that job.
- **Defense validation / no-harm.** It does not test representative benign traffic or real-stack validation beyond the block/pass sample.
- **Control translation.** It does not map patterns into target-control policy syntax.
- **Production safety, deployment, rollout health, and coverage.** It does not approve production, push controls, monitor cohorts, roll back, or emit coverage-facts.
- **Vulnerability check generation.** It does not build or verify proof-of-vulnerability checks; it may use their artifacts as a direct proof basis.

### 8 · DEFERRED — this capability, later

- Additional substrate modalities and control classes beyond the first supported fast-loop and validation-substrate paths.
- Batch testing of multiple samples as one aggregate result.
- Graduated confidence scoring over repeated block observations.
- Richer attribution when multiple controls may have blocked the same sample.
- Learning from bypass-validation and defense-validation outcomes while preserving the block/pass boundary.

### 9 · ASSUMPTIONS

- Candidate mitigation artifacts expose a discriminator and expected block behavior sufficient to construct a test basis.
- At least one validation substrate can apply or represent the first candidate kinds and observe block/pass outcomes.
- Direct proof basis is available only when check-generation has emitted a verified proof-of-vulnerability artifact; otherwise the discriminator path remains useful but weaker.
- Feedback from `not-blocked` is sufficient for defense-generation to revise candidates without knowing mitigation-check internals.
