# control-translation service

Turns a proven mitigation pattern into a control-specific mitigation
candidate for a target technology (Akamai WAF, generic firewall, or an
EDR/S1 stub) — or a grounded reason it cannot be produced. Implements the
Janus `control-translation` Capability Functional Specification (CFS).

## Source provenance

- CFS source: `artifacts/capabilities/cfs-control-translation.md` in the
  `apm0000000-ai-tiger-team-janus` repo (v1.0). See `docs/cfs-source.md`.
- This is a standalone repo, independent of the Janus repo.

## Review docs

- CFS extraction: `docs/cfs-extraction.md`
- POC design: `docs/poc-design.md`
- Implementation / low-level design: `docs/LLD.md`
- Assumptions and follow-ups: `docs/assumptions-and-followups.md`

## What this service does

- Accepts a proven mitigation pattern + target technology/context.
- Reads a current policy snapshot (fixture-backed).
- Calls a translation agent (doer) to propose a candidate rule/config.
- Gates the proposal through deterministic syntax validation and conflict
  detection (judge) before allowing a `translated` verdict.
- Emits a typed `ControlTranslationResult` with one of five terminal
  states: `translated`, `cannot-express`, `insufficient-context`,
  `scope-declined`, `malfunction`.

## What is real vs. fixture-backed

- **Real:** FastAPI HTTP surface, Pydantic contracts, terminal-state
  routing, deterministic syntax/conflict gates, and (when `RUN_MODE=live`)
  a real Pydantic AI agent call to an LLM.
- **Fixture-backed:** policy snapshot reads (no live Akamai/Palo
  Alto/SentinelOne API access), proven-mitigation-pattern samples (no real
  upstream `defense-generation`/`mitigation-check`/`bypass-validation`
  capabilities yet), and the default `FixtureTranslationDoer`.

See `docs/assumptions-and-followups.md` for the full list and backlog.

## Install & run

Requires Python 3.11+ and [uv](https://docs.astral.sh/uv/).

```bash
uv sync
uv run pytest -q
uv run uvicorn control_translation.api:app --reload
```

Then open http://127.0.0.1:8000/ for the demo UI, or
http://127.0.0.1:8000/docs for Swagger UI.

## Configuration

Copy `.env.example` to `.env` and fill in real values as needed:

```bash
cp .env.example .env
```

Default `RUN_MODE=fixture` requires no API key. Set `RUN_MODE=live` and
provide `MODEL_PROVIDER` / `MODEL_NAME` / the matching API key
(`OPENAI_API_KEY` or the Azure OpenAI variables) to use a real Pydantic AI
agent call for translation.

## Invoke

Direct Python:

```python
from control_translation import capability
from control_translation.contracts import ControlTranslationRequest, TargetContext
from control_translation.providers.fixtures import get_fixture_pattern

request = ControlTranslationRequest(
    proven_pattern=get_fixture_pattern("proven-pattern:CVE-EXAMPLE:waf:3"),
    target_context=TargetContext(
        target_technology="akamai-waf",
        target_policy_context_id="akamai-policy:example:rev-17",
    ),
)
result = capability.invoke(request)
```

HTTP:

```bash
curl -sS -X POST http://127.0.0.1:8000/invoke \
  -H 'content-type: application/json' \
  -d @examples/request-translated.json | jq
```

## Terminal states

| State | Meaning |
|---|---|
| `translated` | One primary candidate produced; send to defense-validation. |
| `cannot-express` | Target technology cannot represent the pattern. |
| `insufficient-context` | Missing policy/context; gather and retry. |
| `scope-declined` | Target/config outside coverage, or unresolved policy conflict. |
| `malfunction` | Provider/tooling/result-assembly failure; retry or escalate. |

## Push to target repository

Target repo (provided by you):
`https://github.com/ATT-CSO/apm0047460-Janus-control-translation.git`

This working tree has **no local `.git` directory** so you can add/push it
yourself to a new branch. Example workflow:

```bash
cd control-translation-service
git init
git remote add origin https://github.com/ATT-CSO/apm0047460-Janus-control-translation.git
git checkout -b your-new-branch-name
git add -A
git commit -m "Initial control-translation service: capability core, adapters, agent, API, static UI, tests, docs, Docker/devops handoff"
git push -u origin your-new-branch-name
```

Replace `your-new-branch-name` with the branch you want to deploy from.

## Deployment

This repo does not include CI/CD automation. It includes a `Dockerfile`,
`.dockerignore`, and `docker-compose.yml` as a starting point, plus a full
handoff spec for DevOps at `deploy/DEVOPS-HANDOFF.html` (open it in a
browser) covering image build, required environment variables, secrets
handling, and Azure Container App deployment requirements.

## Open questions

- No live policy-read integration exists for any target technology yet.
- Whether EDR/SentinelOne is in scope for the Janus MVP is unconfirmed.
- Real proven-mitigation-pattern inputs depend on upstream capabilities
  (`defense-generation`, `mitigation-check`, `bypass-validation`) that do
  not exist yet.
