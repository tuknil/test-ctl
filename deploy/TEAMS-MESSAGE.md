# Microsoft Teams handoff message — control-translation service

_Copy and paste this directly into a Teams channel/conversation._

---

🚀 **Control Translation — Databricks write fix ready for deployment**

Hi team — the Control Translation update is ready for PR review and a new
Azure Container Apps revision.

**Repository:**
https://github.com/ATT-CSO/apm0047460-Janus-control-translation

**Root cause confirmed**

The deployed container could connect to Databricks, but normal UI requests
failed while saving with:

`DELTA_NOT_NULL_CONSTRAINT_VIOLATED: request_id`

This was not a bad-token or network-connectivity issue. The browser omitted
`request_id`, while the Databricks result table requires it to be non-null. An
earlier successful test supplied the ID manually and masked the defect.

**What changed**

- The API now generates missing request and correlation IDs before hashing,
	translation, and persistence; caller-provided IDs are preserved.
- Databricks/API/upstream/model failures now include safe operation context and
	complete server-side tracebacks without logging credentials or SQL values.
- The UI shows a sanitized diagnostic panel that can be correlated with
	container logs.
- Regression coverage verifies generated/preserved IDs and diagnostic
	redaction.
- The complete suite passes: **85 tests**.
- Local live validation succeeded with AT&T Inference and Databricks durable
	write/read-back using a normal form request without a request ID.

**DevOps release gate**

1. Build and deploy an immutable image from the new commit; confirm the new
	 revision and image digest receive traffic.
2. Keep approved secret-store references and OAuth M2M Databricks access.
3. Verify `/health`, `/ready`, and `/inference`.
4. Submit a normal request without manually adding `request_id`.
5. Confirm HTTP 200, `Invocation durably persisted`, a row in `/v1/runs`, and
	 read-back from `/v1/results/{result_id}`.
6. Confirm the old NOT NULL error no longer appears.

`/ready` proves connection/read health only; the durable write/read-back is the
required release test.

**Orchestration/Temporal**

The orchestrator can call `POST /invoke` with exact Defense Generation,
Mitigation Check, and Bypass Validation references. Temporal should call it
from an Activity with stable request, correlation, and idempotency identifiers
for retries. Both validated and 10/10 PoC-exhaustion routes are supported;
exhaustion always remains `bypass_cleared=false`.

**Documents**

- Current release and troubleshooting: `deploy/RELEASE-HANDOFF.md`
- Full deployment runbook: `deploy/DEPLOYMENT.md`
- DevOps summary: `deploy/TEAM-DEVOPS-HANDOFF.md`
- Orchestration contract: `docs/orchestration-integration.md`
- Databricks runbook: `docs/databricks-persistence.md`

The service generates a reviewable candidate only. It does not automatically
deploy a rule to Akamai, firewall, EDR, or another target platform.
