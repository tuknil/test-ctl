# CFS — bypass-validation
**Version 1.0**

_Tries to find an adversarial variant that evades a candidate mitigation, producing either a concrete bypass counterexample, a bounded no-bypass-found verdict, or a clear reason the bypass search could not be run._

> **Handoff note:** This CFS defines the capability's functional semantics, externally meaningful outcomes, trust invariants, scope, and boundary. The engineering and implementation owner derives and maintains the production interface and implementation needed to satisfy them. Implementation choices must preserve the meanings and guarantees defined here.

```text
CFS: bypass-validation
Given a candidate mitigation, its discriminator or attack seed, and access to a validation substrate, attempt bounded adversarial variants and emit whether a bypass was found, no bypass was found within the declared bounds, the test could not be run, the request was outside configured coverage, or the capability malfunctioned.
```

### 0 · CONTEXT — problem and solution shape

**Problem.** A mitigation that blocks one known sample can still be weak: encoding, casing, alternate paths, protocol quirks, or small payload mutations may get through. If adversarial pressure is not a separate, structured capability, failed variants disappear into prose and defense-generation receives vague advice instead of concrete counterexamples.

**Solution shape.** Bypass-validation receives one candidate mitigation and a seed attack/discriminator, generates or selects bounded adversarial variants within configured coverage, runs them through a validation substrate, and emits either a bypass counterexample or an honest no-bypass-found/could-not-test result. When a bypass is found, it emits typed feedback that defense-generation can use to revise the candidate without knowing bypass-validation internals.

### 1 · CUSTOMER & JOB

- **Customer:** security engineers and orchestration running the fast mitigation proof loop or evaluating adversarial resilience in a controlled environment.
- **Security question:** can an attacker variant evade this candidate mitigation within the declared bypass-search bounds?
- **Job:** produce a concrete bypass counterexample or a bounded no-bypass-found verdict, with enough evidence for defense-generation or later reviewers to understand what was tried.
- **Safe action:** treat `bypass-found` as proof the candidate failed adversarial pressure and return feedback to defense-generation; treat `no-bypass-found` as bounded evidence that no bypass was found under the declared search profile.
- **Prohibited inference:** `no-bypass-found` does not mean unbypassable, harmless to benign traffic, production-safe, deployed, or population-covering.

### 2 · INVOKE CONTRACT — semantic shapes, not producers

#### Input

The capability accepts semantic inputs. Engineering owns concrete APIs and storage representations while preserving these meanings.

| Input | Meaning and requiredness |
|---|---|
| **Candidate mitigation** | **Required.** Stable identity and artifact reference for the candidate under test, including candidate kind, discriminator/block condition, expected block behavior, assumptions, limitations, collateral-impact prior when available, and provenance. |
| **Seed basis** | **Required.** Attack sample, discriminator sample, verified proof-of-vulnerability artifact, or other seed behavior from which adversarial variants are generated or selected. Includes expected protected behavior and evidence/provenance. |
| **Validation substrate access** | **Required guarantee, not a producer-shaped input.** The runtime can apply or host the candidate mitigation, execute generated variants through the relevant path, and capture observations needed to decide bypassed/blocked/unobservable. The substrate may be a local harness, Docker, iptables/mod_waf environment, dev control stack, SafeBreach-driven lab, vendor sandbox, or another bounded runner. |
| **Bypass profile** | **Required.** Configured coverage for candidate kinds, governed variant families, runner modalities, allowed payload classes, observation points, attempt budget, timeout/resource bounds, and retained-artifact policy. Scope decline is evaluated only against these explicit configured fields. Profiles must use the base variant-family registry names or `custom:family-name` extensions with a definition, owner, and compatibility note. Unknown unqualified variant-family names are invalid profile input and produce `malfunction` because no trustworthy domain result can be emitted from an invalid profile. |
| **Prior proof context** | **Optional but explicit.** Mitigation-check result, prior bypass attempts, known failed variants, do-not-repeat constraints, or proof records. When a mitigation-check result is supplied, it carries result ID, candidate ID, candidate fingerprint ID, test-basis ID, proof basis, proof strength, terminal state, and evidence references. When absent, the request records `prior_block_context: absent`; bypass-validation may still run from a valid seed basis, but it must not imply that mitigation-check passed. |

#### Bypass semantics

A **bypass** is an adversarial variant that reaches or triggers the protected behavior despite the candidate mitigation, where the expected result was block. It must be concrete enough to replay or inspect: request, packet, payload, local stimulus, encoded variant, sequence, or other substrate-supported sample.

`no-bypass-found` means only that no bypass was found within the declared bypass profile, attempt budget, seed basis, and validation substrate. It is not a universal claim that no bypass exists.

Scope decline is limited to explicit configured coverage fields such as candidate kind, variant family, runner modality, payload class, or observation point. A model or agent saying “I do not know how to bypass this” is not scope decline.

#### Variant families

Variant-family names are governed result vocabulary because they drive attempt history, cross-run comparison, and feedback to defense-generation. The base registry is:

- `encoding` — URL, percent, Unicode, base64, compression, or other representation changes;
- `case-normalization` — case changes where the control or target may normalize differently;
- `path-normalization` — path traversal, dot segments, duplicate separators, slash variants, or route normalization;
- `separator` — delimiter, whitespace, boundary, or token-separator changes;
- `method` — HTTP method, verb tunneling, protocol method, or action-shape changes;
- `header` — header presence, duplication, ordering, casing, folding, or value mutation;
- `parameter` — query/form/body parameter name, value, duplication, nesting, or ordering changes;
- `protocol-framing` — framing, chunking, length, transfer encoding, or protocol boundary changes;
- `payload-token-substitution` — semantically equivalent payload token, operator, keyword, or literal substitutions;
- `content-type` — media type, parser-selection, or body-shape changes;
- `ordering` — request, field, rule, packet, or sequence ordering changes;
- `timing` — race, delay, retry, timeout, or pacing variants;
- `control-specific` — evasion family meaningful only for a specific control class or technology;
- `custom:family-name` — extension family with a non-blank definition, owner, and compatibility note.

The bypass profile declares which governed families are in scope for the invocation. Unknown unqualified names are invalid profile input. The result records which families were attempted and which were out of coverage. No product-specific absence claim may be inferred from an unattempted family.

#### Output

The capability emits a **Bypass Validation Result** with:

- `contract_id: bypass-validation@1.0`;
- candidate mitigation identity and artifact reference;
- seed basis identity;
- bypass profile identity;
- validation substrate/run identity;
- one terminal state and non-blank outcome reason;
- attempted variant families and attempt summary;
- concrete bypass counterexample when found;
- feedback package when the result is `bypass-found`;
- evidence/provenance bindings, limitations, gaps, and explicit unknowns; and
- a human-readable prose explanation derived from structured fields.

Illustrative semantic result shape:

```yaml
BypassValidationResult:
  contract_id: bypass-validation@1.0
  result_id: bypass-validation-result:CVE-EXAMPLE:candidate-3:1
  produced_at: 2026-08-11T00:00:00Z
  subject:
    vulnerability_id: CVE-EXAMPLE
    candidate_id: candidate:CVE-EXAMPLE:waf:attempt-3
    candidate_fingerprint_id: candidate-fingerprint:CVE-EXAMPLE:waf:attempt-3
  input_bindings:
    candidate_artifact_id: candidate:CVE-EXAMPLE:waf:attempt-3
    seed_basis_id: test-basis:CVE-EXAMPLE:cmd-metacharacters
    bypass_profile_id: bypass-profile:http-waf:mvp1
    validation_substrate_id: substrate:local-waf-harness
    validation_run_id: substrate-run:local-waf-harness:run-8
    prior_block_context: supplied | absent
    prior_mitigation_check:
      result_id: mitigation-check-result:CVE-EXAMPLE:candidate-3:1
      candidate_id: candidate:CVE-EXAMPLE:waf:attempt-3
      candidate_fingerprint_id: candidate-fingerprint:CVE-EXAMPLE:waf:attempt-3
      test_basis_id: test-basis:CVE-EXAMPLE:cmd-metacharacters
      proof_basis: verified-vuln-artifact | mitigation-discriminator
      proof_strength: direct | indirect
      terminal_state: blocked
      evidence_refs: []
  terminal_state: bypass-found | no-bypass-found | could-not-test | scope-declined | malfunction
  outcome_reason:
    code: bypass-found | no-bypass-within-bounds | observation-unavailable |
      unsupported-variant-family | unsupported-candidate-kind | runner-unavailable |
      invalid-input | result-assembly-failure
    detail: non-blank explanation
  search_bounds:
    variant_families_attempted:
      - encoding
      - path-normalization
    variant_families_out_of_scope: []
    attempt_budget: 25
    attempts_executed: 17
  bypass_counterexample:
    counterexample_id: bypass:CVE-EXAMPLE:candidate-3:encoding-7
    sample_ref: evidence://bypass/encoding-7
    variant_family: encoding
    observed_behavior: reached-protected-target | control-allowed | other
    evidence_refs: []
  feedback:
    feedback_id: mitigation-feedback:attempt-3:bypass
    source: bypass-validation
    rejected_candidate_id: candidate:CVE-EXAMPLE:waf:attempt-3
    failed_gate: bypass
    observed_failure: non-blank when terminal_state is bypass-found
    why_it_sucks: non-blank explanation of the candidate weakness when reusable
    do_not_repeat: non-blank description of the design mistake to avoid when reusable
    counterexample:
      kind: bypass-variant
      reference: evidence://bypass/encoding-7
    evidence_refs: []
    reusable: true | false
    reusable_reason: non-blank
  limitations: []
  prose_summary: non-blank human explanation
```

This is a semantic shape, not a mandated wire format.

#### Invocation and affordances

- **keyed on →** candidate mitigation identity × seed basis identity × bypass profile identity × validation substrate identity × validation run identity.
- **invocation →** asynchronous job. Variant generation, substrate execution, and observation capture are not instant.
- **affords →** `bypass-found` provides concrete feedback for defense-generation. `no-bypass-found` supports moving the candidate forward within the declared bounds. `could-not-test` routes substrate/evidence repair. No result is a no-harm, prod-safe, deployment, or coverage decision.

### 3 · METHOD INVARIANTS — what makes the result trustworthy

- **Must bind to one candidate and one seed basis.** The result cannot aggregate unrelated candidates or unrelated seeds into one verdict unless a later contract version defines aggregation.
- **Must declare search bounds.** Attempt budget, attempted variant families, out-of-scope families, validation substrate identity, and validation run identity are part of the result. `no-bypass-found` is meaningful only inside those bounds.
- **Must use governed variant-family names.** Bypass profiles and results use base registry names or valid `custom:family-name` extensions. Unknown unqualified family names make the bypass profile invalid and produce `malfunction`, not a domain verdict.
- **Must require executed attempts for `no-bypass-found`.** A `no-bypass-found` verdict requires at least one executed adversarial attempt within the declared profile. If no attempt executes, the result is `scope-declined`, `could-not-test`, or `malfunction` according to why execution did not occur.
- **Must use the validation substrate as the execution boundary.** Variants run only through the supplied substrate/runner and never against production or arbitrary live targets.
- **Must ground bypass verdicts in substrate observations.** `bypass-found` and `no-bypass-found` are based on executed attempts and observations, not model confidence or prose.
- **Must emit concrete counterexample on `bypass-found`.** A bypass verdict requires a replayable or inspectable variant plus evidence that it reached or triggered behavior the mitigation should have blocked.
- **Must emit feedback on `bypass-found`.** The result includes a typed feedback package with observed failure, counterexample, `why_it_sucks`, `do_not_repeat` when reusable, `reusable`, `reusable_reason`, and evidence references.
- **Must define feedback reusability.** `reusable: true` means the bypass explains a real candidate weakness that defense-generation should avoid repeating in the current loop. It requires the finding to apply to the same selected control class, discriminator or candidate-fingerprint dimension, and bypass-profile scope with concrete replayable evidence. `reusable: false` preserves the evidence but does not require defense-generation to carry it forward as a do-not-repeat lesson.
- **Must not turn unsupported variants into no-bypass evidence.** Variant families outside configured coverage are recorded as out of scope and cannot support `no-bypass-found` for those families.
- **Must distinguish untestable from no bypass.** If the substrate cannot apply the candidate, execute variants, or observe pass/block behavior, emit `could-not-test` or `scope-declined`, not `no-bypass-found`.
- **Must decline unsupported coverage explicitly.** A valid candidate kind, seed basis, variant family, runner modality, or observation point outside configured coverage yields `scope-declined`, not `no-bypass-found` or `malfunction`.
- **Must not claim no-harm, collateral impact, or production safety.** Evasion resistance under a bounded adversarial search says nothing about benign traffic, collateral impact, or production exposure. The capability may preserve variant metadata, but it does not emit collateral-impact verdicts or priors.
- **Must not emit coverage-facts or residual labels.** This capability emits adversarial evidence and feedback only.
- **Must keep prose non-authoritative.** Structured fields are the contract; prose explains them.

### 4 · EMIT & PERSIST — results and terminal states

#### Persist and emit

Persist valid results by stable result identity. Persist validation substrate identity, validation run identity, candidate artifact reference, seed basis, attempted variants, bypass counterexample when found, search bounds, feedback package, limitations, and evidence bindings. Emit safe observable exhaust: variant-generation summaries, sample execution traces, control/protected-target observations, and runner/provider failures. Do not persist secrets or unredacted sensitive payloads outside policy.

Structured fields are authoritative. The prose summary is display-only and must not introduce conclusions absent from structured fields.

#### Terminal-state field matrix

| Terminal state | Assertion | Counterexample | Search bounds | Feedback | Safe action | Must not infer | Escalation |
|---|---|---|---|---|---|---|---|
| `bypass-found` | A concrete adversarial variant evaded the candidate mitigation within the declared bounds. | **Required.** | Required. | **Required.** | Return feedback to defense-generation. | All variants bypass; the control class can never work. | No human required unless policy asks for review. |
| `no-bypass-found` | At least one adversarial attempt executed and no bypass was found within the declared search bounds, attempted families, budget, validation substrate, and validation run. | Absent. | **Required**, with `attempts_executed` greater than zero. | Optional. | Candidate may move forward in the workflow under bounded assurance. | The candidate is unbypassable, safe for production, or untested families were searched. | No human required solely for this result. |
| `could-not-test` | The capability could not reach a trustworthy bypass verdict because required substrate, candidate application, variant execution, or observation was unavailable. | Absent unless safely gathered before failure. | Required when attempts began. | Optional diagnostic feedback only. | Repair substrate/evidence/context and retry. | No bypass exists or bypass exists. | Route to substrate/evidence owner. |
| `scope-declined` | Input is valid but candidate kind, seed basis, variant family, runner modality, payload class, or observation point is outside configured coverage. | Absent. | Optional. | Absent. | Use supported configuration or capability version. | Candidate resisted bypass; substrate broke. | No retry until coverage/config changes. |
| `malfunction` | A valid domain result could not be emitted because input parsing, runner/tooling, persistence, or result assembly failed. | Optional partial diagnostics only. | Optional partial diagnostics only. | Absent as trusted feedback. | Repair and retry or escalate to capability/runtime owner. | Any domain conclusion about bypassability. | Human/retry required. |

#### State rules

- `bypass-found` wins when any executed variant produces an attributable bypass.
- `no-bypass-found` requires at least one executed attempt and must carry search bounds. Zero executed attempts cannot produce `no-bypass-found`.
- `could-not-test` wins when missing substrate/observation context could change the bypass conclusion.
- `scope-declined` wins before adversarial work for valid requests outside configured coverage.
- `malfunction` wins only when no trustworthy domain result can be emitted.
- Out-of-scope variant families cannot support `no-bypass-found`; they are listed as untested/out of coverage.

### 5 · ACCEPTANCE CRITERIA — prove the contract

**Done =** a customer can tell whether a bypass was found, no bypass was found within stated bounds, or the bypass search could not be run—and can pass concrete counterexample feedback to defense-generation when needed.

#### Invariant-to-check mapping

| Invariant | Observable check |
|---|---|
| One candidate / one seed | Result identity and subject bind exactly one candidate and one seed basis. |
| Search bounds explicit | `no-bypass-found` includes attempted variant families, attempt budget, attempts executed greater than zero, validation substrate identity, and validation run identity. |
| Substrate boundary | Invocation cannot use arbitrary production target coordinates as the test path. |
| Observation-grounded verdicts | `bypass-found` and `no-bypass-found` cite substrate observations, run identity, and attempt records. |
| Concrete counterexample | `bypass-found` includes a replayable/inspectable counterexample and evidence refs. |
| Feedback on bypass | `bypass-found` includes typed feedback for defense-generation with `why_it_sucks`, `do_not_repeat` when reusable, and `reusable_reason`. |
| Unsupported variants excluded | Out-of-scope variant family is listed and does not count as searched. |
| Untestable distinction | Missing observation point yields `could-not-test`, not `no-bypass-found`. |
| Scope explicit | Unsupported runner/variant/payload class yields `scope-declined`. |
| Boundary preserved | No result claims no-harm, collateral-impact verdict, prod-safe, deployment, rollout health, or coverage-fact. |
| Prose non-authority | Removing prose does not remove any domain conclusion. |

#### Conformance scenarios

| Scenario | Expected terminal outcome | Security meaning | Must not happen |
|---|---|---|---|
| URL-encoded variant bypasses a candidate WAF pattern and reaches the protected handler | `bypass-found` | Candidate failed adversarial pressure; feedback includes the encoded counterexample. | Report no-bypass-found because the original sample was blocked. |
| Bounded search over encoding and path-normalization families finds no passing variant after 25 attempts | `no-bypass-found` | No bypass was found within stated bounds. | Claim the candidate is unbypassable. |
| Browser-session variant family is requested but outside configured coverage | `scope-declined` | Request is valid but unsupported by this invocation. | Treat as no-bypass-found. |
| Substrate cannot observe whether variants reached the protected target | `could-not-test` | Bypass result is unknown. | Treat absence of evidence as no bypass. |
| Runner crashes before attempts are recorded | `malfunction` | No trustworthy domain result exists. | Emit diagnostic feedback as if a bypass was found. |
| Agent says it cannot think of a bypass, but no attempts were executed | `malfunction` or `could-not-test` depending failure cause | A model assertion alone is not a search. | Emit no-bypass-found. |
| Bypass profile references unknown unqualified family `uri-transform` | `malfunction` | Variant-family names must come from the governed registry or valid custom extension before a domain verdict can be emitted. | Emit incomparable variant-family evidence. |
| Bypass is real but applies only because the lab failed to apply the candidate | `bypass-found` only if attributable bypass evidence exists; feedback has `reusable: false` | Evidence is retained, but defense-generation is not required to carry it forward as a design lesson. | Mark it reusable and force a false do-not-repeat lesson. |

### 6 · GUARANTEES DEPENDED ON — the “we do not care how” boundary

- **Validation substrate / isolated runner.** The runtime can apply or host the candidate mitigation, execute variants through the relevant path, bind execution to the supplied candidate/substrate, enforce time/resource limits, and capture control/protected-target observations or a typed unavailable result. It supplies distinct validation substrate identity and validation run identity for every execution. [integrate]
- **Candidate and seed-basis access.** The runtime supplies candidate mitigation artifact, discriminator, expected block behavior, and seed sample with stable identity and provenance. [provided]
- **Prior mitigation-check context.** When available, the runtime supplies mitigation-check result ID, candidate ID, candidate fingerprint ID, test-basis ID, proof basis, proof strength, terminal state, and evidence references. When unavailable, it supplies explicit absent context. [provided]
- **Adversarial generation or corpus access.** The capability has access to supported variant-generation roles, evasion corpora, or deterministic mutation tools declared by the bypass profile, using governed variant-family names. [provided]
- **Observation capture.** The substrate can capture enough evidence to distinguish bypassed, blocked, and unobservable for supported runner modalities. [provided]
- **Artifact/result persistence.** Results, variant attempts, counterexamples, feedback packages, substrate run IDs, and evidence references can be persisted with stable identity. [provided]
- **Secret and sensitive-data controls.** Candidate artifacts, samples, generated variants, substrate logs, and traces are stored or redacted according to policy; secrets are not emitted in results. [provided]

### 7 · BOUNDARY — not this capability, ever

- **Generating or revising mitigations.** Defense-generation creates candidates; this capability tests adversarial variants against them.
- **Proof-of-mitigation block/pass for one known sample.** Mitigation-check owns the initial block/pass oracle.
- **Defense validation / no-harm.** It does not test representative benign traffic or real-stack validation beyond bypass attempts.
- **Control translation.** It does not map patterns into target-control policy syntax.
- **Production safety, deployment, rollout health, and coverage.** It does not approve production, push controls, monitor cohorts, roll back, or emit coverage-facts.
- **Vulnerability check generation.** It does not build or verify proof-of-vulnerability checks; it may use their artifacts as seed basis.

### 8 · DEFERRED — this capability, later

- Additional governed variant families beyond the first configured attack/control classes.
- Batch or campaign-level bypass search over many seeds as one aggregate result.
- Graduated confidence scoring over repeated no-bypass-found outcomes.
- Multi-control or chained-control bypass validation.
- Learning from defense-validation and production observations while preserving this CFS boundary.

### 9 · ASSUMPTIONS

- Candidate mitigation artifacts expose a discriminator, expected block behavior, and enough structure to generate or select adversarial variants.
- At least one validation substrate can apply or represent the first candidate kinds and observe bypass outcomes.
- Bypass feedback is sufficient for defense-generation to revise candidates without knowing bypass-validation internals.
- Reusable feedback can be distinguished from non-reusable evidence based on whether the bypass explains a real candidate weakness in the current loop.
- A bounded no-bypass-found result is useful only when adversarial attempts actually executed, and it is not a universal bypass-resistance claim.
