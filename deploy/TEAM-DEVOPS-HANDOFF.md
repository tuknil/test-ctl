# [F-13 Blue Face] control-translation service — team & DevOps handoff

**Repo:** https://github.com/ATT-CSO/apm0047460-Janus-control-translation  
**Capability:** `control-translation`  
**Status:** Initial build complete and pushed. Functional in fixture/demo mode.  
**Blocker:** Need real syntax formats for Akamai WAF, Palo Alto firewall, and SentinelOne (S1) EDR.  
**Forecast delivery:** 08/24/2026 pending receipt of those formats.

---

## TL;DR for the team

The service framework is done, containerized, and can be deployed. The remaining work is replacing fixture/placeholder translation artifacts with real target syntax once we get the canonical formats from the control owners. I built through the blocker so we don’t lose time.

---

## What was built

- **FastAPI HTTP service** with endpoints:
  - `GET /health`
  - `GET /schema`
  - `POST /invoke`
  - `GET /runs/{run_id}`
- **Swagger UI** at `/docs` and a **static HTML/JS demo UI** at `/`.
- **Pydantic contracts** matching the Janus `control-translation` CFS.
- **Terminal states:** `translated`, `cannot-express`, `insufficient-context`, `scope-declined`, `malfunction`.
- **Adapters:** `akamai-waf`, `firewall-generic` (Palo placeholder), `edr-s1` stub.
- **Translation agent:** `FixtureTranslationDoer` by default; `RUN_MODE=live` switches to a real Pydantic AI call using the API key in `.env`.
- **Deterministic judge gates:** syntax validation and conflict detection.
- **Container artifacts:** `Dockerfile`, `.dockerignore`, `docker-compose.yml`, and `deploy/DEVOPS-HANDOFF.html`.
- **Docs:** `README.md`, `docs/LLD.md`, `docs/cfs-extraction.md`, `docs/poc-design.md`, `docs/assumptions-and-followups.md`.

---

## Known blocker — team ask

I need the real target-control syntax formats so the adapter layer can emit deployable artifacts instead of templates:

1. **Akamai WAF** — rule XML/config format and CLI/API schema.
2. **Palo Alto firewall** — rule JSON/XML/CLI schema (security/NAT/policy objects).
3. **SentinelOne (S1) EDR** — policy/rule format for custom detection or containment.

Without these, the service produces a best-effort `akamai-waf-rule` / `firewall-rule` / `edr-rule` template and labels it as such in `limitations`. It is **not** ready to push to a real tenant.

If you can connect me to the SMEs or repos that own these formats, I can turn the blocker around quickly.

---

## Assumptions I made

- **Policy snapshots are fixture-backed.** No live Akamai, Palo Alto, or SentinelOne API integration exists yet.
- **Proven mitigation patterns are fixtures.** Upstream Janus capabilities (`defense-generation`, `mitigation-check`, `bypass-validation`) do not exist yet, so sample patterns are hard-coded.
- **Default mode is fixture.** `RUN_MODE=fixture` requires no API key. `RUN_MODE=live` needs `MODEL_PROVIDER`, `MODEL_NAME`, and the matching API key (`OPENAI_API_KEY` or Azure OpenAI variables).
- **Syntax/conflict validation is fixture-backed.** The judge gates run against canned data, not a live target tenant.
- **EDR/S1 is a stub.** Scope confirmation for SentinelOne in the Janus MVP is pending; the adapter is minimal and will be expanded once syntax is confirmed.
- **Translated artifacts are templates.** All `translated` results are marked with limitations and should be validated before any real deployment.

---

## DevOps next steps

1. **Build locally:**
   ```bash
   docker build -t control-translation .
   ```
2. **Run locally with fixture mode (no API key):**
   ```bash
   docker run -p 8000:8000 control-translation
   ```
3. **Environment / secrets:**
   - Copy `.env.example` to `.env` and set real values only if enabling `RUN_MODE=live`.
   - In Azure Container Apps, expose port `8000` and mount the API key as a secret if using live mode.
   - Fixture mode does **not** need any API key.
4. **Full deploy guide:** Open `deploy/DEVOPS-HANDOFF.html` in a browser.

---

## Call to action

- **Team:** Please provide or point me to canonical syntax formats for Akamai WAF, Palo Alto firewall, and S1 EDR.
- **DevOps:** Review `deploy/DEVOPS-HANDOFF.html` and let me know if the Dockerfile / compose / env setup needs changes for the Azure Container App target.

— Saleem
