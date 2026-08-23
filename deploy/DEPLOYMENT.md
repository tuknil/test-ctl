# Control Translation — DevOps Deployment Handoff

## 1. Deployment status

This repository is ready to deploy as a **controlled internal POC/demo service**.
It is not approved for unrestricted production or direct Internet exposure.
See [Production gaps](#12-production-gaps-before-general-availability) before promoting it beyond an internal environment.

The service:

- exposes a FastAPI API and static demo UI;
- supports deterministic fixture mode and live model mode;
- can call AT&T Inference through an OpenAI-compatible endpoint;
- validates model output with target-specific syntax and conflict checks;
- returns a reviewable candidate and never deploys a control automatically.

## 2. Build artifact

Build from the repository root:

```bash
docker build -t <registry>/control-translation:<version> .
docker push <registry>/control-translation:<version>
```

Use an immutable release tag or image digest in the deployment. Do not deploy `latest` as the only reference.

The image:

- uses Python 3.11;
- starts with `python -m control_translation`;
- reads its bind host and port from environment variables;
- does not copy `.env`, tests, local virtual environments, caches, or credentials;
- performs a container health check against `/ready`.

## 3. Ports and routes

| Item | Value |
|---|---|
| Container port | `8000` by default; configurable with `PORT` |
| Protocol | HTTP inside the platform; terminate TLS at the gateway/ingress |
| Liveness | `GET /health` |
| Readiness | `GET /ready` |
| API invocation | `POST /invoke` |
| Swagger | `GET /docs` when `ENABLE_DOCS=true` |
| Demo UI | `GET /` |
| Team flow page | `GET /demo.html` |

Recommended probes:

- liveness: path `/health`, initial delay 10 seconds, interval 30 seconds;
- readiness: path `/ready`, initial delay 10 seconds, interval 30 seconds;
- timeout: 5 seconds;
- unhealthy threshold: 3 failures.

`/ready` returns HTTP `503` when runtime or live-model configuration is invalid.

## 4. Environment variables to give DevOps

Give DevOps the variable **names and approved non-secret values** below. Give secret values only through the deployment platform's secret store—not email, chat, tickets, source control, build arguments, or a committed `.env` file.

### 4.1 Internal fixture/demo deployment

No model endpoint or API key is required:

```dotenv
RUN_MODE=fixture
MODEL_PROVIDER=none
MODEL_NAME=not-configured
MODEL_REQUEST_TIMEOUT_SECONDS=60
HOST=0.0.0.0
PORT=8000
ENABLE_DOCS=true
```

Use this mode for repeatable UI demonstrations, API integration testing, and smoke tests without model cost.

### 4.2 Live AT&T Inference deployment

Provide these non-secret values to DevOps:

```dotenv
RUN_MODE=live
MODEL_PROVIDER=att-inference
MODEL_NAME=<APPROVED_ATT_MODEL_ID>
ATT_INFERENCE_BASE_URL=<APPROVED_OPENAI_COMPATIBLE_BASE_URL>
MODEL_REQUEST_TIMEOUT_SECONDS=60
HOST=0.0.0.0
PORT=8000
ENABLE_DOCS=false
```

Create this secret in the platform secret store:

```text
ATT_INFERENCE_API_KEY=<ROTATED_APPROVED_SECRET>
```

Map the secret to the container environment variable `ATT_INFERENCE_API_KEY` at runtime.

Do not send DevOps a developer `.env` file containing a key. Any key previously displayed in a screen share, transcript, ticket, or log must be revoked and rotated before deployment.

### 4.3 Other optional provider variables

Only configure the selected provider:

| Provider | Variables |
|---|---|
| Public OpenAI | `MODEL_PROVIDER`, `MODEL_NAME`, secret `OPENAI_API_KEY` |
| Azure OpenAI | `MODEL_PROVIDER`, `MODEL_NAME`, `AZURE_OPENAI_ENDPOINT`, `AZURE_OPENAI_API_VERSION`, secret `AZURE_OPENAI_API_KEY` |
| AT&T Inference | `MODEL_PROVIDER=att-inference`, `MODEL_NAME`, `ATT_INFERENCE_BASE_URL`, secret `ATT_INFERENCE_API_KEY` |

Never set multiple provider API keys unless required by the approved platform design.

## 5. Secret handling requirements

1. Use an approved managed secret store.
2. Inject keys as runtime secret references.
3. Do not bake secrets into the image or pass them as Docker build arguments.
4. Restrict secret-read access to the service identity and deployment operators.
5. Prevent environment dumps and authorization headers from entering logs.
6. Configure rotation and revoke the old value after validation.
7. Scan the repository and image before promotion.

The application does not return the API key or LLM base endpoint from `/inference`, `/schema`, or `/invoke`.

## 6. Recommended platform controls

Place the service behind an enterprise API gateway or internal ingress with:

- TLS;
- caller authentication and authorization;
- network allowlists/private ingress;
- rate limits and model-cost quotas;
- request-body size limits;
- connection and upstream timeouts;
- centralized access logs with sensitive-field redaction;
- correlation/request IDs;
- Web Application Firewall controls as required by platform policy.

The application does not currently implement caller authentication itself. Do not expose it directly to the public Internet.

## 7. Azure Container Apps example mapping

Use the team's approved templates and naming standards. The logical settings are:

| Azure Container Apps setting | Recommended value |
|---|---|
| Ingress | Internal/private unless explicitly approved |
| Target port | `8000` |
| Transport | HTTP/auto |
| Min replicas | `1` for a live demo |
| Max replicas | `1` until durable run storage is added |
| Liveness path | `/health` |
| Readiness path | `/ready` |
| CPU/memory starting point | `0.5` CPU / `1 GiB`, then tune from metrics |
| Secret | `att-inference-api-key` or approved naming equivalent |
| Env secret reference | `ATT_INFERENCE_API_KEY` → secret reference |

The service stores `/runs/{run_id}` results in process memory. Multiple replicas can still process `/invoke`, but a later run lookup may reach a different replica and return `404`. Keep one replica or disable reliance on run lookup until durable storage is implemented.

## 8. Deployment sequence

1. Run CI tests and container build.
2. Scan dependencies and the image with approved security tooling.
3. Push the image with an immutable version tag.
4. Create/update runtime secrets in the platform secret store.
5. Deploy first in fixture mode.
6. Confirm `/health`, `/ready`, `/schema`, `/`, and a fixture `/invoke` request.
7. Switch the non-production deployment to live mode and inject the rotated model secret.
8. Confirm `/ready` returns `200`.
9. Invoke the approved CVE-2017-5638/Akamai example.
10. Confirm the response reports `inference.llm_invoked=true` and contains no secret or endpoint.
11. Review logs and model usage, then obtain application/security owner approval before promotion.

Mode changes require a new revision/restart because configuration is loaded when the process starts.

## 9. Smoke tests

After deployment, replace `<service-base-url>` with the gateway URL.

```bash
curl -fsS <service-base-url>/health
curl -fsS <service-base-url>/ready
curl -fsS <service-base-url>/inference
curl -fsS -X POST <service-base-url>/invoke \
  -H 'content-type: application/json' \
  --data-binary @examples/request-translated.json
```

Expected checks:

- `/health` returns `{"status":"ok"}`;
- `/ready` returns `{"status":"ready"}`;
- `/inference` returns mode/provider/model and only a credential boolean;
- `/invoke` returns one documented terminal state;
- a successful live request reports `llm_invoked: true`;
- no response or log contains an API key or authorization header.

The local `examples/` directory is not included in the runtime image. Run the final command from a checked-out repository or an approved API test runner.

## 10. Observability and alerts

Capture at minimum:

- request count and latency by endpoint/status;
- terminal-state count;
- provider-call latency and failure count;
- readiness failures;
- HTTP `4xx`/`5xx` counts;
- model token/cost/quota metrics where available;
- container restarts and memory/CPU saturation.

Do not log full API keys, authorization headers, complete policy snapshots, or candidate content without approved data classification and redaction.

Recommended alerts:

- `/ready` failing for more than five minutes;
- elevated `malfunction` or provider-failure rate;
- model quota/rate-limit errors;
- repeated container restarts;
- abnormal invocation volume or cost.

## 11. Rollback

1. Keep the prior known-good image digest and configuration revision.
2. Roll back the application revision without reusing or exposing old secrets.
3. If the failure is model-related, switch to `RUN_MODE=fixture` only for an approved demo/test fallback; do not represent fixture output as live production behavior.
4. Validate `/health`, `/ready`, and one known fixture request after rollback.

The service never pushes rules to target products, so application rollback does not require removing a rule deployed by this service.

## 12. Production gaps before general availability

The following are application/product dependencies, not tasks DevOps can solve only through deployment configuration:

- live, authenticated, read-only policy readers for Akamai/firewall/EDR;
- trusted upstream proof-record retrieval and verification;
- durable run/result storage for restarts and horizontal scaling;
- target-owner acceptance tests against non-production target tenants;
- provider retry/backoff, circuit breaking, and formal model quotas;
- prompt/model version governance and adversarial evaluation;
- formal human approval, change management, rollback, and ownership workflow;
- confirmed SentinelOne scope and canonical target formats.

A `translated` response means the candidate passed the validators currently implemented. It does not mean a vendor accepted it or that it is approved for production deployment.

## 13. DevOps handoff checklist

- [ ] Immutable image built, tested, scanned, and pushed
- [ ] Internal ingress/gateway configured
- [ ] TLS and caller authentication enabled
- [ ] Rate and request-size limits enabled
- [ ] Non-secret environment values approved
- [ ] API key stored and injected as a secret reference
- [ ] Previously exposed key rotated
- [ ] Liveness and readiness probes configured
- [ ] Single replica configured until durable storage exists
- [ ] Central logging and redaction verified
- [ ] Alerts configured
- [ ] Fixture smoke test passed
- [ ] Approved live-mode smoke test passed
- [ ] Application, target-control, security, and DevOps owners signed off
