# Microsoft Teams handoff message — control-translation service

_Copy and paste this directly into a Teams channel/conversation._

---

🚀 **[F-13 Blue Face] control-translation service — initial build is live on GitHub**

Hi team — the first build of the `control-translation` capability is done and containerized, ready for DevOps review. I hit one blocker that needs input from control SMEs.

**Repo:** https://github.com/ATT-CSO/apm0047460-Janus-control-translation

**What’s ready**
- FastAPI service with `/health`, `/schema`, `/invoke`, `/runs/{run_id}`
- Swagger UI + static demo UI
- Pydantic contracts matching the Janus `control-translation` CFS
- Adapters for Akamai WAF, generic firewall (Palo placeholder), and S1 EDR stub
- Fixture-backed policy reader and proven mitigation samples
- Dockerfile, docker-compose, and DevOps handoff

**Blocker: I need canonical syntax formats**
To move from “template” to deployable artifacts, I need the real rule/config formats for:
- **Akamai WAF**
- **Palo Alto firewall**
- **SentinelOne (S1) EDR**

If you own any of these or know the right SMEs/docs, please drop links or reach out.

**Key assumptions I made**
- No live policy API integration yet — everything is fixture-backed.
- Upstream Janus capabilities (`defense-generation`, `mitigation-check`, `bypass-validation`) don’t exist yet, so inputs are sample patterns.
- Default mode is `fixture` (no API key). Switch to `RUN_MODE=live` + `.env` for real Pydantic AI calls.
- Generated candidates are templates marked with limitations until real syntax is validated.

**DevOps:** Full build/deploy guide is in `deploy/DEVOPS-HANDOFF.html`. Port `8000`, no secrets needed for fixture mode.

**Ask**
1. SMEs — share target syntax formats / control schemas.
2. DevOps — review the handoff and Azure Container App deployment steps.
3. Everyone — the handoff doc with full detail is in the repo at `deploy/TEAM-DEVOPS-HANDOFF.md`.

Target delivery is still **08/24** pending those syntax formats. Thanks!

— Saleem
