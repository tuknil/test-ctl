# CFS source provenance

This service implements the `control-translation` Capability Functional
Specification (CFS) from the Janus repository:

- **Source path (origin repo):**
  `artifacts/capabilities/cfs-control-translation.md`
  in `apm0000000-ai-tiger-team-janus`.
- **Version implemented:** 1.0.

The full CFS text is the authoritative semantic contract. It is not
duplicated verbatim here to avoid drift between two copies; instead, refer
to the source file in the Janus repo. Key sections mapped to this service:

| CFS section | Where implemented in this repo |
|---|---|
| §2 Invoke contract (input/output shapes) | `src/control_translation/contracts.py` |
| §3 Method invariants | `src/control_translation/capability.py`, `src/control_translation/translation/engine.py` |
| §4 Terminal-state field matrix + state rules | `src/control_translation/terminal.py`, `src/control_translation/capability.py` |
| §6 Guarantees depended on (`[integrate]` items) | `src/control_translation/policy_reader/`, `src/control_translation/adapters/` (fixture-backed; real integration is future work) |
| §7 Boundary | Explicitly not implemented — see `docs/assumptions-and-followups.md` |
| §8 Deferred | Backlog — see `docs/assumptions-and-followups.md` |

If the source CFS changes, re-check `contracts.py`, `terminal.py`, and
`capability.py` against the new text before relying on this service.
