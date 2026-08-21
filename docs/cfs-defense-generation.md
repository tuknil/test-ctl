# CFS — defense-generation
**Version 1.0**

_Turns a characterized threat and selected control class into one primary candidate mitigation pattern for the fast proof loop, reusing prior Janus-emitted candidates when they fit and carrying the discriminator, assumptions, collateral-impact prior, and proof-feedback history needed to test and revise it._

> **Handoff note:** This CFS defines the capability's functional semantics, externally meaningful outcomes, trust invariants, scope, and boundary. The engineering and implementation owner derives and maintains the production interface and implementation needed to satisfy them. Implementation choices must preserve the meanings and guarantees defined here.

```text
CFS: defense-generation
Given a characterized threat, a selected viable control class, supporting evidence, prior Janus-emitted mitigation candidates, generation policy, and optional typed proof feedback, reuse, adapt, or produce one primary candidate mitigation pattern for the configured fast validation substrate—or emit a bounded, evidence-backed reason no candidate can be produced.
```

### 0 · CONTEXT — problem and solution shape

**Problem.** A mitigation idea is easy to state vaguely and hard to make testable. Without a capability boundary, the same work gets blurred across grading, proof, real-control translation, and deployment: one component decides a class might work, another invents a rule, another tests it, and failed attempts disappear into prose. The same mistake also appears across runs: a later invocation can reinvent a mitigation candidate Janus already emitted, proved, validated, or even deployed, losing lineage and risking regression. That causes repeated bad candidates, ungrounded broad blocks, and confusion between “no candidate,” “not enough context,” and “the real technology cannot express this.”

**Solution shape.** Defense-generation receives a selected control class, threat characterization, and any relevant prior Janus-emitted mitigation candidates before producing a new candidate. It checks whether a prior candidate fits the current discriminator, selected class, constraints, and generation policy; reuses or adapts that candidate when supported; otherwise it builds one primary candidate mitigation pattern for the configured fast-loop substrate. It consumes typed feedback from prior proof attempts when revising. It emits a candidate pattern with discriminator, expected block behavior, assumptions, collateral-impact prior, reuse lineage, and attempt history—or a structural non-positive result. It does not prove the candidate, translate it to a production control technology, or deploy it.

### 1 · CUSTOMER & JOB

- **Customer:** security engineers and orchestration that need a testable mitigation candidate for a selected control class.
- **Security question:** can an existing Janus-emitted candidate be reused or adapted for this characterized threat and selected control class, or must a new candidate mitigation pattern be produced, and what exactly should the fast proof loop test?
- **Job:** produce a primary candidate mitigation pattern—reused, adapted, or newly generated—that can be passed to proof capabilities without re-deriving a defensive idea Janus already has, or emit a clear reason no candidate is available from this generation attempt.
- **Safe action:** send `candidate-produced` output to mitigation-check and bypass-validation in the fast proof loop; use non-positive outcomes to gather missing context, choose another class, or route residual/evidence-gap handling.
- **Prohibited inference:** a candidate is not proven effective, bypass-resistant, harmless, production-safe, target-technology-expressible, deployed, or population-covering.

### 2 · INVOKE CONTRACT — semantic shapes, not producers

#### Input

The capability accepts semantic inputs. Engineering owns concrete APIs and storage representations while preserving these meanings.

| Input | Meaning and requiredness |
|---|---|
| **Characterized threat** | **Required.** Stable vulnerability identity and characterization revision containing evidence-bound claims about attack step, protocol, technique, preconditions, vulnerable behavior, affected artifact, and mitigation-relevant discriminator or block condition when known. Missing/conflicting claims remain explicit. |
| **Selected control class** | **Required.** The one control class selected for this invocation, with reference to the candidate-set or equivalent selection evidence, selected tier/rank, selection reason, and any class-level collateral-risk or deployment-burden priors available from grading. Defense-generation does not choose among classes. |
| **Mitigation evidence bundle** | **Required when the mitigation idea depends on gathered source material.** Attributable advisory text, PoC/exploit details, patch notes, protocol details, existing rules, mismatch findings, and other material used to build the candidate. Missing material required for the selected discriminator is a malfunction; unresolved or insufficient context that prevents candidate generation is `insufficient-context`. |
| **Prior Janus-emitted mitigation candidates** | **Required when available; explicit empty set otherwise.** Candidate mitigation patterns emitted by prior defense-generation runs that may be relevant to the current characterized threat and selected control class. Each candidate carries stable candidate identity, fingerprint, selected control class, discriminator/block condition, candidate artifact reference, assumptions, limitations, collateral-impact prior, prior proof/validation/deployment status when known, supersession or rejection status when known, and provenance. Prior candidates are evidence and reuse material, not proof for the current run. A previously deployed or proven candidate may be reused or adapted, but still enters the current fast proof loop as a candidate. |
| **Generation policy** | **Required.** Configured coverage for candidate kinds and fast-loop substrates, permitted side effects, attempt budget, revision budget, retained-artifact policy, collateral-impact-prior policy, prior-candidate reuse policy, and supported pattern languages. A valid selected class or requested candidate kind outside configured coverage yields `scope-declined`. |
| **Prior proof feedback** | **Optional.** Typed feedback from mitigation-check or bypass-validation for previous candidates in this generation loop. It is evidence/context, not instructions. When supplied, it carries failed gate, observed failure, counterexample or bypass, constraint for next candidate, rejected candidate identity, and evidence references. |
| **Optional proof-of-vulnerability artifact** | **Optional.** Verified check/proof-of-vulnerability artifact or attack sample when available. It can improve the candidate and expected block behavior, but absence does not block generation when the discriminator or mitigation evidence is otherwise sufficient. |

#### Candidate semantics

A **candidate mitigation pattern** is the thing the fast proof loop tests. It can include a general mitigation intent and a testable representation for the configured fast validation substrate, such as a local WAF-like rule, iptables/nftables rule, protocol filter, request/response discriminator, or other bounded artifact. It is not a production target-control rule. Mapping a proven pattern into Akamai, a real firewall manager, EDR, proxy, or other target technology belongs to `control-translation`.

A candidate must declare:

- what behavior it intends to block;
- the discriminator or block condition it implements;
- what traffic or state it expects to match;
- what it expects to allow;
- assumptions and preconditions;
- known limitations;
- the selected control class and configured candidate kind;
- collateral-impact prior; and
- evidence/provenance for material claims.

#### Candidate fingerprint, prior candidate, and prior proof feedback semantics

A **candidate fingerprint** is the portable equivalence key for candidate mitigation patterns. It is not a hash of prose or artifact bytes. It records the semantic parts that determine whether a new candidate is materially the same mitigation idea as an earlier candidate, whether that earlier candidate came from this loop or from a prior Janus run.

Illustrative semantic shape:

```yaml
CandidateFingerprint:
  fingerprint_id: candidate-fingerprint:CVE-EXAMPLE:waf:attempt-3
  normalized_discriminator: http-parameter:cmd:shell-metacharacters
  block_condition_class: request-parameter-pattern | header-pattern | path-pattern | protocol-state | rate-shape | local-artifact-state | other
  match_primitives:
    - parameter-name:cmd
    - character-class:shell-metacharacters
  match_scope:
    paths: [/api/v1/diag]
    methods: [POST]
    protocols: [http]
  normalization_handling:
    url-decoding: single-pass
    case-folding: false
    unicode-normalization: none
  allowlist_assumptions: []
  side_effect_profile: blocks-request | drops-packet | logs-only | rate-limits | other
  candidate_kind: fast-waf-rule
```

Two candidates are materially equivalent for the do-not-repeat and prior-reuse rules when they have the same normalized discriminator, block condition class, material match primitives, match scope, normalization/encoding handling, allowlist assumptions, side-effect profile, and candidate kind, even if their prose, formatting, or generated artifact bytes differ. A new candidate may intentionally reuse part of a failed fingerprint only when the result explains which failed constraint no longer applies.

A **prior Janus-emitted mitigation candidate** is a candidate pattern produced by an earlier defense-generation run. Its proof, validation, or deployment history can help rank reuse, but does not make it proven for the current run. Reuse means emitting the prior pattern as the current run's primary candidate with current-run identity and prior lineage. Adaptation means changing bounded parts of the prior candidate to fit current evidence or constraints while preserving the reusable defensive idea. Both still require current mitigation-check and bypass-validation.

Illustrative semantic shape:

```yaml
PriorMitigationCandidate:
  prior_candidate_id: candidate:CVE-OLD:waf:attempt-2
  prior_result_id: defense-generation-result:CVE-OLD:waf:1
  candidate_fingerprint_id: candidate-fingerprint:CVE-OLD:waf:attempt-2
  selected_control_class: waf
  discriminator:
    description: non-blank block condition
    evidence_refs: []
  candidate_artifact_ref: artifact-store:defenses/CVE-OLD/attempt-2
  prior_status:
    proof: untested | blocked | not-blocked | bypassed | unknown
    validation: untested | validated | failed | unknown
    deployment: never-deployed | deployed | rolled-back | unknown
  supersession_status: current | superseded | rejected | unknown
  assumptions: []
  limitations: []
  provenance: []
```

Prior proof feedback is a structured memory of what failed. It prevents repeated failed candidates without welding defense-generation to proof-capability internals.

Illustrative semantic shape:

```yaml
MitigationFeedback:
  feedback_id: proof-feedback:attempt-2
  source: mitigation-check | bypass-validation
  rejected_candidate_id: candidate:attempt-2
  failed_gate: block | bypass | policy | observation
  observed_failure: non-blank description
  counterexample:
    kind: attack-sample | bypass-variant | blocked-benign | policy-violation | none
    reference: evidence://counterexample/2
  constraint_for_next_candidate: non-blank bounded constraint
  evidence_refs: []
  reusable: true | false
```

The capability must consider supplied feedback, preserve it in attempt history, and avoid regenerating materially equivalent rejected candidates unless it emits a reason why the old constraint no longer applies.

#### Output

The capability emits a **Defense Generation Result** with:

- `contract_id: defense-generation@1.0`;
- subject vulnerability/characterization identity;
- selected control class and selection binding;
- generation policy identity;
- one terminal state and non-blank outcome reason;
- one primary candidate on `candidate-produced`;
- reuse decision and prior-candidate lineage when prior candidates were supplied;
- optional alternate or discarded candidates as supporting artifacts only;
- attempt and proof-feedback history;
- collateral-impact prior object on every emitted candidate;
- evidence/provenance bindings, confidence, limitations, gaps, and conflicts; and
- a human-readable prose explanation derived from structured fields.

Illustrative semantic result shape:

```yaml
DefenseGenerationResult:
  contract_id: defense-generation@1.0
  result_id: defense-generation-result:CVE-EXAMPLE:waf:1
  produced_at: 2026-08-07T00:00:00Z
  subject:
    vulnerability_id: CVE-EXAMPLE
    characterization_revision_id: characterization:CVE-EXAMPLE:1
  input_bindings:
    selected_control_class: waf
    candidate_set_result_id: mitigator-grade-result:CVE-EXAMPLE:1
    selection_reason: top-ranked viable class under workflow policy
    generation_policy_id: defense-gen-policy:mvp1
    prior_candidate_ids:
      - candidate:CVE-OLD:waf:attempt-2
    proof_feedback_ids: []
  terminal_state: candidate-produced | no-candidate | insufficient-context | scope-declined | malfunction
  outcome_reason:
    code: candidate-produced | unsupported-candidate-kind | no-candidate-survived |
      insufficient-discriminator | insufficient-policy-context | invalid-input |
      provider-failure | result-assembly-failure
    detail: non-blank explanation
  reuse_decision:
    decision: reused-prior | adapted-prior | generated-new | none-applicable
    prior_candidate_refs:
      - candidate:CVE-OLD:waf:attempt-2
    reason: non-blank explanation
  primary_candidate:
    candidate_id: candidate:CVE-EXAMPLE:waf:attempt-3
    candidate_fingerprint:
      fingerprint_id: candidate-fingerprint:CVE-EXAMPLE:waf:attempt-3
      normalized_discriminator: http-parameter:cmd:shell-metacharacters
      block_condition_class: request-parameter-pattern
      match_primitives:
        - parameter-name:cmd
        - character-class:shell-metacharacters
      match_scope:
        paths: [/api/v1/diag]
        methods: [POST]
        protocols: [http]
      normalization_handling:
        url-decoding: single-pass
        case-folding: false
        unicode-normalization: none
      allowlist_assumptions: []
      side_effect_profile: blocks-request
      candidate_kind: fast-waf-rule
    selected_control_class: waf
    candidate_kind: fast-waf-rule | fast-firewall-rule | protocol-filter | other
    mitigation_intent: non-blank intent
    discriminator:
      description: non-blank block condition
      expected_block_behavior: non-blank expected blocked behavior
      evidence_refs: []
    candidate_artifact:
      artifact_type: mod_waf-rule | iptables-rule | nftables-rule | local-harness-rule | abstract-pattern | other
      content_ref: artifact-store:defenses/CVE-EXAMPLE/attempt-3
      content_hash: sha256:example
      emitted_as: candidate-mitigation-pattern
    collateral_impact_prior:
      verdict: low | medium | high | unknown | abstained
      confidence: high | medium | low | unknown
      basis: non-blank explanation
      gaps: []
      measured: false
    prior_candidate_lineage:
      source_candidate_id: candidate:CVE-OLD:waf:attempt-2 | null
      reuse_type: reused-prior | adapted-prior | none
      preserved_fingerprint: true | false
      adaptation_summary: non-blank when adapted
    assumptions: []
    limitations: []
    provenance: []
  attempt_history:
    - candidate_id: candidate:CVE-EXAMPLE:waf:attempt-2
      candidate_fingerprint_id: candidate-fingerprint:CVE-EXAMPLE:waf:attempt-2
      outcome: rejected-by-feedback | policy-invalid | generated-invalid | superseded
      feedback_refs: []
      do_not_repeat_constraints: []
      equivalence_decision:
        compared_to: candidate-fingerprint:CVE-EXAMPLE:waf:attempt-3
        materially_equivalent: false
        reason: non-blank explanation when compared
  evidence_bindings:
    - claim: discriminator | expected-block-behavior | collateral-impact-prior | limitation
      evidence_refs: []
  prose_summary: non-blank human explanation
```

This is a semantic shape, not a mandated wire format.

#### Invocation and affordances

- **keyed on →** vulnerability identity × characterization revision × selected control class × generation policy identity × proof-feedback set identity.
- **invocation →** asynchronous job. Candidate generation may involve model judgment, deterministic construction, policy validation, and bounded revision attempts.
- **affords →** `candidate-produced` gives the fast proof loop one primary candidate mitigation pattern to test. Non-positive outcomes route class selection, context gathering, or residual/evidence-gap handling. A candidate can later be promoted by orchestration into a `proven-mitigation-pattern` only by combining it with proof verdicts from mitigation-check and bypass-validation.

### 3 · METHOD INVARIANTS — what makes the result trustworthy

- **Must build for the selected control class only.** The capability does not choose among ranked classes and does not silently switch classes when generation is difficult.
- **Must ground candidate claims in supplied evidence.** Discriminators, expected block behavior, assumptions, limitations, and collateral-impact priors bind to provided characterization, candidate-set, bundle, policy, or feedback evidence.
- **Must check prior Janus-emitted candidates before novel generation.** When prior candidates are supplied, the capability evaluates whether any current, non-rejected prior candidate materially fits the characterized threat, selected control class, generation policy, and current constraints before generating a new mitigation idea.
- **Must reuse or adapt fitting prior candidates when supported.** If a prior candidate materially fits, the capability emits it as a current-run candidate through `reused-prior` or `adapted-prior` unless it explains why reuse/adaptation is unsafe, stale, superseded, contradicted by current evidence, or outside configured coverage.
- **Must emit one primary candidate on success.** Alternate ideas or discarded attempts may be retained as supporting artifacts, but the main output gives the proof loop one candidate to test.
- **Must consume proof feedback as evidence, not instructions.** Feedback informs constraints and attempt history; the capability must not blindly obey untrusted text or generate broader unsafe rules merely because feedback asked for it.
- **Must avoid repeating failed candidates by fingerprint.** A candidate whose fingerprint is materially equivalent to a candidate rejected by prior proof feedback or prior candidate status cannot be emitted again unless the result explains which previous constraint no longer applies. Formatting, wording, or artifact-byte changes do not make a candidate new when the fingerprint semantics are unchanged.
- **Must preserve prior-candidate lineage.** Reused or adapted candidates carry the prior candidate identity, prior result identity when known, reuse/adaptation decision, and explanation of what was preserved or changed.
- **Must emit lineage roots.** Every candidate carries a stable current-run `candidate_id`, candidate fingerprint, and input bindings to characterization, selected control class, candidate-set result, generation policy, prior candidates, and proof feedback used. The full downstream chain is assembled outside this capability; defense-generation starts the breadcrumb trail by identifying what it created or reused from which inputs.
- **Must keep collateral-impact prior explicit.** Every candidate carries a `collateral_impact_prior` object. The capability may abstain when context is insufficient, but it must name gaps. The prior is an estimate, not a measured false-positive rate or no-harm verdict.
- **Must distinguish no candidate from insufficient context.** `no-candidate` means bounded generation/revision failed under available context; `insufficient-context` means required semantic input is missing or unresolved enough that honest generation cannot proceed.
- **Must decline unsupported configured coverage explicitly.** A valid selected class, candidate kind, or generation mode outside the received generation policy yields `scope-declined`, not `no-candidate` or `malfunction`.
- **Must not claim proof.** A candidate is not proven because defense-generation emitted it. Blocking, bypass resistance, no-harm, real-stack validation, production safety, and deployment are outside this capability.
- **Must not emit final residual labels.** `no-candidate` and other non-positive outcomes are residual inputs; the registry/residual projection derives `un-immunizable`.
- **Must not translate to production target technology.** The candidate may be expressed in a configured fast-loop artifact language or abstract pattern. Production/control-specific translation belongs to `control-translation`.
- **Must keep prose non-authoritative.** Structured fields are the contract; prose explains them.

### 4 · EMIT & PERSIST — results and terminal states

#### Persist and emit

Persist valid results by stable result identity. Persist candidate artifacts, candidate fingerprints, discarded attempts when retained by policy, proof feedback references, equivalence decisions, collateral-impact prior basis, and evidence bindings. Emit safe observable exhaust: generation summaries, validation/policy checks, rejected-candidate summaries, do-not-repeat constraints, and model/provider failures. Do not persist secrets or unredacted sensitive data.

Structured fields are authoritative. The prose summary is display-only and must not introduce conclusions absent from structured fields.

#### Terminal-state field matrix

| Terminal state | Assertion | Candidate artifact | Feedback/attempt history | Safe action | Must not infer | Escalation |
|---|---|---|---|---|---|---|
| `candidate-produced` | One primary candidate mitigation pattern was reused, adapted, or generated for the selected control class under the generation policy. | **Required** primary candidate with current-run candidate ID, fingerprint, collateral-impact prior, reuse decision, and prior lineage when applicable. | Required; may be empty if first attempt. | Send primary candidate to fast proof loop. | Candidate works, resists bypass, is harmless, translates to real tech, is deployable, or remains valid because it was previously deployed. | No human required solely for generation. |
| `no-candidate` | Bounded generation/revision could not produce a candidate worth testing under available context and policy. | Absent as primary candidate; failed attempts may be retained. | Required when attempts occurred. | Try another selected class, change policy/context, or route as residual/evidence-gap input. | No mitigation exists anywhere; selected class was unfit; target technology cannot express it. | No human required unless policy asks for review. |
| `insufficient-context` | Required discriminator, characterization, selected class, evidence, policy, or feedback context is missing/unresolved enough that honest generation cannot proceed. | Absent. | Optional. | Gather named missing context and retry. | Candidate generation was attempted and failed; no defense exists. | Route to owner of missing context. |
| `scope-declined` | Input is valid, but selected class, candidate kind, or generation mode is outside configured generation coverage. | Absent. | Absent unless helpful for explanation. | Use a supported configuration or a capability version that supports it. | Selected class is unfit or no defense exists. | No retry until scope/config changes. |
| `malfunction` | A valid domain result could not be emitted because required input parsing, provider/model/tooling, persistence, or result assembly failed. | Absent as trusted artifact. | Optional partial diagnostics only. | Repair and retry or escalate to capability/runtime owner. | Any domain conclusion about mitigation availability. | Human/retry required. |

#### State rules

- `candidate-produced` requires one primary candidate and no claim that proof has already passed for the current run.
- `candidate-produced` may come from `reused-prior`, `adapted-prior`, or `generated-new`; reused/adapted prior candidates still enter the current fast proof loop.
- `no-candidate` requires disclosed attempt exhaustion or policy-governed refusal under sufficient context.
- `insufficient-context` wins over `no-candidate` when missing or unresolved input could plausibly change whether a candidate can be generated.
- `scope-declined` wins before generation for valid requests outside configured coverage.
- `malfunction` wins only when no trustworthy domain result can be emitted.
- `candidate-produced` with `collateral_impact_prior.verdict=abstained` is valid if the prior object names the missing context and policy does not require a known prior.

### 5 · ACCEPTANCE CRITERIA — prove the contract

**Done =** a customer can take a `candidate-produced` result and run the fast proof loop against one primary candidate, or route a non-positive result without inventing why no candidate exists.

#### Invariant-to-check mapping

| Invariant | Observable check |
|---|---|
| Selected class honored | Given selected class `waf`, output does not silently switch to firewall or EDR. |
| Evidence grounding | Candidate discriminator, expected block behavior, assumptions, and limitations cite supplied evidence. |
| Prior candidate check | Supplied prior Janus-emitted candidates are evaluated before novel generation, and the result records the reuse decision. |
| Prior candidate reuse/adaptation | A materially fitting prior candidate is reused or adapted unless the result explains why reuse/adaptation is unsafe, stale, superseded, contradicted, or out of coverage. |
| One primary candidate | Positive result has exactly one primary candidate; alternates are not the main output. |
| Feedback as evidence | Prior proof feedback appears in attempt history and constraints, not as untrusted instructions copied into the rule. |
| Do-not-repeat | A candidate materially equivalent by fingerprint to a rejected prior or feedback candidate is not re-emitted without an explicit reason. |
| Lineage roots | Candidate output includes current-run `candidate_id`, candidate fingerprint, prior-candidate lineage when applicable, and input bindings sufficient for orchestration to chain later proof/translation/validation/deployment records. |
| Collateral-impact prior explicit | Every candidate has a prior object; abstention names gaps and `measured=false`. |
| Outcome distinction | Missing discriminator yields `insufficient-context`; bounded failed attempts with sufficient context yield `no-candidate`; unsupported candidate kind yields `scope-declined`; provider failure yields `malfunction`. |
| No proof claim | Positive output contains no block/pass, bypass-resistant, no-harm, prod-safe, deployed, or coverage-fact claim. |
| No target-tech translation | Candidate is a fast-loop pattern/artifact, not Akamai/FW/EDR production config. |
| Prose non-authority | Removing prose does not remove any domain conclusion. |

#### Conformance scenarios

| Scenario | Expected terminal outcome | Security meaning | Must not happen |
|---|---|---|---|
| HTTP injection discriminator, selected WAF class, sufficient evidence, and no relevant prior candidates | `candidate-produced` with `generated-new` | One new WAF-pattern candidate is available for fast proof. | Claim it is proven or production deployable. |
| Prior Janus-emitted WAF candidate has a materially matching fingerprint, is not rejected or superseded, and its assumptions still fit current evidence | `candidate-produced` with `reused-prior` | A prior candidate is reused as the current run's candidate for fast proof. | Invent a new equivalent candidate or skip current mitigation-check/bypass-validation because the prior candidate existed. |
| Prior deployed WAF candidate matches the current discriminator but current evidence requires a narrower path constraint | `candidate-produced` with `adapted-prior` | A previously emitted/deployed candidate was adapted with lineage and still requires current proof. | Treat prior deployment as proof that the adapted candidate is safe or already deployable. |
| Prior bypass feedback shows the last candidate failed on URL encoding; new output incorporates a constraint avoiding that bypass and has a materially different fingerprint | `candidate-produced` | Feedback was used as evidence to revise the candidate. | Re-emit the same failed candidate with no explanation. |
| New candidate changes only prose/formatting while preserving the same fingerprint as a rejected candidate | `no-candidate` if no non-equivalent candidate is produced | The do-not-repeat rule is semantic, not byte/prose based. | Treat superficial edits as a new candidate. |
| Selected class is valid but requested candidate kind is outside generation policy | `scope-declined` | The request is outside configured coverage. | Emit `no-candidate` or `malfunction`. |
| Required discriminator is missing or conflicts with the evidence bundle | `insufficient-context` | More characterization/evidence is needed before generation. | Invent a broad block condition. |
| Sufficient context exists, but all bounded attempts are invalid, overbroad, or unusable under policy | `no-candidate` | This run could not produce a candidate worth testing. | Claim no mitigation exists anywhere. |
| Model/tool provider returns invalid structured output or artifact persistence fails | `malfunction` | No trustworthy domain result exists. | Emit a fabricated candidate or supported negative. |
| Candidate collateral impact cannot be estimated because no benign profile/policy context exists | `candidate-produced` if policy allows abstention | Candidate exists, but impact prior abstained with gaps. | Omit the prior field or report measured false-positive rate. |
| Caller asks for Akamai production rule output | `scope-declined` under this CFS | Target-control translation is outside defense-generation. | Generate production config in this capability. |

### 6 · GUARANTEES DEPENDED ON — the “we do not care how” boundary

- **Typed characterized threat and discriminator context.** The runtime supplies the vulnerability characterization, selected class binding, and evidence bundle with stable identities and provenance. [provided]
- **Prior candidate access.** The runtime can provide relevant prior Janus-emitted mitigation candidates with stable identities, fingerprints, artifacts, assumptions, limitations, status, and provenance, or an explicit empty set. [provided]
- **Generation policy delivery.** The runtime supplies supported classes, candidate kinds, fast-loop substrate targets, attempt/revision budgets, retained-artifact policy, collateral-impact-prior policy, prior-candidate reuse policy, and supported pattern languages for the invocation. [provided]
- **Model/tool judgment for construction and adaptation.** The capability has access to judgment/construction roles capable of reusing, adapting, producing candidate mitigation patterns, and revising them from typed feedback. [provided]
- **Artifact persistence.** Candidate artifacts, attempt summaries, feedback references, and result records can be persisted with stable identity and provenance. [provided]
- **Safe handling for proof feedback and source artifacts.** Counterexamples, PoCs, payloads, and source material are treated as evidence and are not executed or copied into artifacts outside policy. [provided]

### 7 · BOUNDARY — not this capability, ever

- **Choosing the control class.** It consumes the selected class; class ranking and selection come from grading/orchestration policy.
- **Proof-of-mitigation.** It does not decide whether the candidate blocks the attack.
- **Bypass validation.** It does not decide whether an attacker can evade the candidate.
- **Defense validation / no-harm.** It does not validate the candidate on real/dev-equivalent gear or representative benign traffic.
- **Control translation.** It does not map a proven pattern into Akamai, firewall manager, EDR, proxy, or other target-control production syntax/config.
- **Deployment, rollout health, and coverage facts.** It does not push controls, monitor live cohorts, roll back, or emit coverage-facts.
- **Final residual.** It emits residual inputs such as `no-candidate`; it does not emit final `un-immunizable`.

### 8 · DEFERRED — this capability, later

- Additional fast-loop candidate artifact kinds beyond the first supported WAF/firewall-like patterns.
- Richer collateral-impact priors calibrated against later defense-validation outcomes.
- Richer retrieval/ranking over large prior-candidate corpora; this version assumes relevant candidates are supplied to the invocation.
- Multi-candidate batch output, if a later workflow needs parallel proof exploration.
- Candidate generation for control classes outside configured coverage.
- Automated learning from successful control-translation and defense-validation outcomes, while preserving this CFS's boundary.

### 9 · ASSUMPTIONS

- The selected control class is supplied by grading/orchestration and is viable enough to attempt.
- The first build targets have enough discriminator/evidence context to generate, reuse, or adapt at least some candidate patterns.
- Relevant prior Janus-emitted candidates can be supplied to the invocation when they exist; absence is explicit rather than silently assumed.
- The fast proof loop can feed typed mitigation-check and bypass-validation feedback back into this capability.
- A candidate mitigation pattern is a useful handoff to proof capabilities even before target-control translation exists.
- Collateral-impact prior is useful as an explicit estimate/abstention, but measured no-harm belongs to defense-validation.
