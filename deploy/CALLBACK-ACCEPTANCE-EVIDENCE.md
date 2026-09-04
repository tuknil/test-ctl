# Control Translation Callback Acceptance Evidence

Use this record for the deployed Control Translation revision. Do not paste the
callback bearer token, secret value, authorization header, or unredacted
environment output into this file.

Evidence collection date: `2026-09-03`

## Deployment Identity

| Evidence | Value |
|---|---|
| Azure Container App | `<container-app-name>` |
| Resource group | `<resource-group>` |
| Deployed revision name | `<revision-name>` |
| Immutable image digest | `<registry/repository@sha256:digest>` |
| Capability | `control-translation` |

## Secret Reference

- [ ] `CAPABILITY_CALLBACK_TOKEN` is configured through an Azure Container Apps
  secret reference rather than a literal environment value.
- Secret reference name: `<secret-reference-name>`
- Redacted configuration evidence: `<command output, portal screenshot, or change record>`
- [ ] Evidence contains no secret value or bearer authorization header.

## Submit Evidence

- Submit timestamp: `<UTC timestamp>`
- Submit HTTP status: `202`
- Request ID: `<control-translation-request-id>`
- Correlation ID: `<correlation-id>`
- Capability run ID: `<control-translation-run-id>`
- Temporal child workflow ID: `<workflow-id; do not provide a workflow run ID>`
- Accepted callback signal: `janus.capability-completion.v1`
- Redacted log excerpt showing callback metadata acceptance:

```text
<Callback metadata accepted ... token omitted/redacted>
```

## Callback Evidence

- Callback event ID: `control-translation:<run-id>:terminal:v1`
- Callback attempt timestamp: `<UTC timestamp>`
- Callback endpoint response: `202 Accepted`
- Response body:

```json
{
  "event_id": "control-translation:<run-id>:terminal:v1",
  "status": "accepted"
}
```

- Redacted service log excerpt:

```text
<Callback delivery accepted event_id=... run_id=... attempts=...>
```

## Polling Fallback Evidence

- [ ] Submit a separate run without callback headers, or disable callback
  delivery in a controlled test revision.
- Poll status endpoint: `GET /v1/control-translation-runs/<run-id>`
- Poll result endpoint: `GET /v1/control-translation-runs/<run-id>/result`
- Final lifecycle status: `completed`
- Domain terminal state: `<translated|not-translatable>`
- Status/result evidence: `<redacted response or test record>`

## Automated Test Mapping

| Requirement | Automated coverage |
|---|---|
| Persist all callback headers | `test_submit_accepts_and_persists_all_callback_headers` |
| Polling-only submit | `test_submit_without_callback_headers_remains_polling_only` |
| Incomplete header group | `test_submit_rejects_incomplete_callback_header_group` |
| One logical terminal event | `test_completed_domain_outcomes_create_one_logical_callback` |
| Exact callback identifiers | `test_callback_payload_has_only_required_identifiers` |
| Stable event ID across retries | `test_retryable_responses_back_off_and_reuse_event_id` |
| `202` completes delivery | `test_202_marks_delivery_complete` |
| Safe `401` alert | `test_401_alerts_without_exposing_token_or_canonical_result` |
| `429` and `5xx` backoff | `test_retryable_responses_back_off_and_reuse_event_id` |
| Duplicate safety | `test_duplicate_dispatch_does_not_change_canonical_result` |
| Status/result remain available | `test_callback_failure_keeps_http_status_and_result_available` |
| Commit before delivery | `test_terminal_state_and_result_exist_before_http_delivery` |
