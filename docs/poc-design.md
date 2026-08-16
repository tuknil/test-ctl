# POC design — control-translation

Following `janus-capability-poc` internal-composition conventions.

```text
Internal composition type: hybrid
Mechanical gates:
  - adapter.supports_feature() cheap pre-check before agent call
  - syntax_validator.validate() after agent proposal
  - conflict_checker.detect_conflicts() after syntax validation
  - terminal-state precedence in capability.py (scope-declined >
    insufficient-context > cannot-express > malfunction > translated)
Pydantic AI agent roles:
  - translation_agent (doer): proposes candidate_content + translation_label
    + justification + assumptions/limitations, typed as TranslationProposal
Judge/verifier roles:
  - syntax_validator + conflict_checker act as the deterministic judge over
    the doer's proposal; the doer's output is never trusted until both gates
    pass
Fanout unit: none — one proven pattern x one target technology per invocation
Fanout source: n/a (CFS defines a single-candidate output; no per-target
  fanout in this release, see CFS §8 deferred "multiple candidates per
  target")
Fanout cardinality rule: n/a
Aggregation/ranking rule: n/a (one primary candidate only, per CFS §3)
Retry/repair loop: none in this release — a failed doer call or failed
  judge gate routes directly to a terminal state; no bounded repair loop
Terminal routing rule: see docs/cfs-extraction.md precedence table;
  implemented in capability.py::invoke
What is deterministic:
  - adapter registry resolution
  - supports_feature() pre-check
  - syntax_validator / conflict_checker gates
  - terminal-state routing
What is model-judged:
  - the specific candidate_content text and translation_label proposed by
    the doer (fixture doer is template-based/deterministic; live doer is a
    real Pydantic AI agent call)
What is fixture-backed in this POC:
  - PolicyReader (FixturePolicyReader)
  - ProvenMitigationPattern samples (providers/fixtures.py)
  - FixtureTranslationDoer (default RUN_MODE)
  - All three target adapters' policy-conflict comparisons (compare against
    fixture snapshots only, no live API)
What requires live providers/tools:
  - LiveTranslationDoer (RUN_MODE=live) needs a configured model
    provider/API key via .env
  - Real live-policy reads for Akamai/Palo Alto/SentinelOne are NOT
    implemented; PolicyReader has no live implementation in this release
```

## Answer-kind mapping

The single agent role (`translation_agent`) emits **construction**: a new
artifact (`candidate_content`) with a location (embedded in the result) and
a verification status supplied by the downstream judge gates, not by the
agent itself.

## Doer/judge separation

- **Doer:** `agents/translation_agent.py` (`FixtureTranslationDoer` or
  `LiveTranslationDoer`), proposes but does not decide terminal state.
- **Judge:** `translation/syntax_validator.py` +
  `translation/conflict_checker.py`, both deterministic, both run after
  every doer call before a `translated` verdict is possible.

Raw LLM text never becomes a trusted fact: `LiveTranslationDoer` uses a
Pydantic AI `Agent` with `output_type=TranslationProposal`, so the model's
response is bound to that Pydantic model before this service touches it,
and the judge gates run identically regardless of which doer produced the
proposal.
