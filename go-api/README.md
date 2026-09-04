# control-translation — Go API service (lean)

One execution path: read the proven ModSecurity `SecRule` from the Databricks
rows the request names, compile it into an Akamai custom WAF rule, gate it, and
persist the result in Databricks.

There is no model client, no fallback doer, and no second target technology.
A rule the compiler cannot express with certainty returns `cannot-express` —
never a guess.

Callers reach it synchronously on `POST /invoke` or through the durable
asynchronous lifecycle.

## Run it

```bash
cd go-api && go test ./... && go run ./cmd/api
```

Databricks is the only backend, so `/ready` fails until it is configured:

```bash
DATABRICKS_SERVER_HOSTNAME=... DATABRICKS_HTTP_PATH=/sql/1.0/warehouses/... \
DATABRICKS_CLIENT_ID=... DATABRICKS_CLIENT_SECRET=... \
DATABASE_PATH=./data/lifecycle.db \
CORS_ALLOWED_ORIGINS=http://127.0.0.1:8080 go run ./cmd/api
```

## Endpoints

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/` | service descriptor |
| `GET` | `/health` | liveness |
| `GET` | `/ready` | readiness, including the Databricks reachability probe |
| `GET` | `/inference` | runtime status; always reports no model |
| `GET` | `/schema` | the contract this build actually accepts |
| `POST` | `/invoke` | read the referenced rows and compile the proven rule |
| `POST` | `/v1/control-translation-runs` | queue the same work asynchronously |
| `GET` | `/v1/control-translation-runs/{run_id}` | poll durable lifecycle status |
| `GET` | `/v1/control-translation-runs/{run_id}/result` | read the immutable result |
| `POST` | `/v1/control-translation-runs/{run_id}/cancel` | request idempotent cancellation |
| `GET` | `/v1/runs` | bounded dashboard page |
| `GET` | `/runs/{run_id}` | durable completion envelope |
| `GET` | `/v1/results/{result_id}` | durable business result |
| `GET` | `/openapi.json` | the OpenAPI 3.1 document |
| `GET` | `/docs` | Swagger UI |
| `GET` | `/redoc` | ReDoc |

## API documentation

`ENABLE_DOCS=true` (the default) serves `/openapi.json` with Swagger UI at
`/docs` and ReDoc at `/redoc`. `ENABLE_DOCS=false` removes all three routes
entirely and stops the service descriptor advertising them, so a
gateway-fronted or closed deployment does not publish its own surface.

The document is hand-authored rather than generated, so it describes what the
service actually accepts -- the two `/invoke` forms, the header contract on the
async submit, which fields are rejected -- instead of what a struct tag
implies. It also says the thing a generator would never say: **a decline is a
200 with a typed body, not an error status**, so a caller must read
`terminal_state` rather than switch on the HTTP code.

The cost of hand-authoring is drift, so a test cross-checks the document's
paths and methods against the route table in both directions: a route missing
from the document fails, and a documented path that is not routed fails. Both
directions are verified to fail on real drift, not just asserted. A second test
holds the advertised `TerminalState` enum to the states the service can emit.

The two renderers load their assets from a public CDN, the same posture
FastAPI's built-in `/docs` has in the Python service. A deployment without
egress to that CDN gets an unstyled page; `/openapi.json` still serves the
document, and it is the machine-readable artifact that matters.

## Where the rule comes from

`POST /invoke` accepts two forms.

**Referenced (the production form).** The envelope carries `contract_id`,
`subject`, `upstream_inputs`, `routing_context` and `provenance`. The three
`upstream_inputs[].result_ref` entries name the Databricks rows to read:

| Capability | Table | Read for |
|---|---|---|
| `defense-generation` | `36889_janus_dev.defense_generation.defense_generation_results` | **the rule** — `primary_candidate.artifact_content` — plus the discriminator and control class |
| `mitigation-check` | ``36889_janus_dev.`mitigation-check`.mitigation_check`` | proof that the rule blocked, and its lineage |
| `bypass-validation` | `36889_janus_dev.bypass_validation.bypass_validation_results` | proof of no bypass, or the counterexample for an exhausted loop |

Exactly those three rows are read, by `result_id`, from those three approved
tables. A reference pointing anywhere else is refused before any row is
fetched, and a query returning more than one row is an error rather than a
pick-the-first.

Before anything is compiled, the resolver checks that all three rows agree on
correlation, subject revision, vulnerability, and candidate; that each row's
`result_id` matches the reference that named it; that each is in its required
terminal state; and that the producer identity on the row is the expected one.
Any mismatch is `insufficient-context` with no candidate — the point of the
read is that the service must never compile a rule belonging to a different
candidate.

The response echoes the three references it read in `reference_bundle`, and
records the route in `proof_loop_qualification`. On the PoC-exhaustion route
the candidate is still emitted but carries an explicit *not bypass-cleared*
limitation and the bypass counterexample.

**Direct.** An inline `input.proven_pattern` is used as-is, for fixtures and
local testing.

Either way `callback` and the async lifecycle fields are not accepted, and a
partial orchestration envelope is a 422 rather than a silent fallback to the
direct form.

## The asynchronous lifecycle

Submission requires `Idempotency-Key` and `X-Correlation-ID`; the body's
`request_id` must equal the idempotency header and its `correlation_id` the
correlation header. An identical retry returns the same run; the same key with
different input is a `409`. The optional `X-Janus-Callback-*` header group is
all-or-none — a partial group is rejected — and is then ignored: this build has
no callback dispatcher, so callers poll.

A background worker claims one run at a time under a lease, heartbeats while
translating, and reclaims leases that expired because a process died.
`WORKER_MAX_ATTEMPTS` bounds that recovery, so a run that keeps failing ends
terminally `failed` rather than cycling forever.

**Completion order matters.** The immutable result is written to Databricks
first; only then is the queue row marked complete. A crash between the two
leaves the run claimable, and the results write is a `MERGE` keyed on
`result_id`, so the retry cannot produce a duplicate row. The queue row never
holds the result — only a pointer to it and the compact completion (reference,
SHA-256, byte size), which is what `GET .../result` follows back to Databricks.

Cancellation wins before a result exists. Afterwards the completion wins,
because the result is already in the immutable table and may already have been
consumed.

## Connecting to Databricks

Either four variables:

```bash
DATABRICKS_SERVER_HOSTNAME=adb-7405605071306757.17.azuredatabricks.net
DATABRICKS_HTTP_PATH=/sql/1.0/warehouses/866109ed7dfce51a
DATABRICKS_AUTH_TYPE=pat
DATABRICKS_TOKEN=<pat>
```

or one, in the `databricks-sql-go` connection-string format:

```bash
DATABRICKS_DSN='token:<pat>@adb-7405605071306757.17.azuredatabricks.net:443/sql/1.0/warehouses/866109ed7dfce51a'
```

A `databricks://` scheme prefix is optional, and `?catalog=&schema=` are
honored. A DSN carries a personal access token, so it selects PAT auth; OAuth
M2M is not expressible as a DSN and needs the explicit variables.

**Explicit variables win over the DSN**, so one field can be changed without
rewriting the string, and an explicit `DATABRICKS_AUTH_TYPE=oauth-m2m` is not
switched to PAT behind your back by a token in the DSN.

The DSN holds a secret, which is the reason to think twice about it: a single
string is easy to paste into a ticket, a shell history, or a `ps` listing,
where four separate variables are not. The service never logs its settings, a
malformed DSN is reported by name without echoing the value, and a test asserts
the token appears in none of `/`, `/ready`, `/inference`, `/schema`,
`/openapi.json`, or the process logs. Everything outside this process is on
you.

## Persistence

The split follows the Python service: **SQLite coordinates, Databricks
stores.**

The lifecycle queue is a local SQLite file at `DATABASE_PATH` — the one piece
of local state — because a Delta table has no row locks and makes a poor queue.
Its schema and `schema_migrations` bookkeeping match migration 2 of
`src/control_translation/persistence/migrations.py`. Mount it on durable
storage and run exactly one replica; `SERVICE_REPLICA_COUNT != 1` fails
readiness. Losing the file forgets in-flight runs, but any result already
written to Databricks survives.

Everything durable and shareable goes to Databricks. The write is a `MERGE` that inserts only
when the `result_id` is absent, so a retry can never overwrite a published
result; the row is then read back and its digest and byte size compared
against what was sent. `request_id` doubles as the idempotency key: a repeat
returns the stored envelope, and the same key with different input is a 409.

The table shape matches the one the Python service writes
(`src/control_translation/persistence/databricks.py`), so rows written by
either are readable by the other.

Access is over the SQL Statement Execution REST API, not a JDBC driver, which
is why the binary stays static and the image needs no libc. Caller input is
always sent as an out-of-band statement parameter; nothing is concatenated
into SQL text.

## Encoding ladders

Defense generation often enumerates recursive URL-encodings of a single
character per alternation group:

```
person(?:\[|%5B|%255B|%25255B|%2525255B|%252525255B|%25252525255B)0(?:\]|%5D|...)...
```

Akamai `value` entries are flat wildcard strings with no alternation, so a
positional expansion of five such groups is a cross-product: 7^5 = 16,807
values, well past the 32-value cap, and the rule would decline.

The compiler recognizes a group whose every branch is the previous branch
URL-encoded once more, and aligns all such groups to a common depth. Real
traffic encodes a body uniformly; a body with `[` raw but `]` double-encoded is
not a case worth enumerating. The result is **one value per depth** — seven,
not 16,807:

```
*person[0][]=malicious*
*person%5B0%5D%5B%5D%3Dmalicious*
*person%255B0%255D%255B%255D%253Dmalicious*
...
```

Every emitted value is one the source rule matches, so the candidate is a
strict subset of the source and can never over-block. A test asserts that
property directly by running each emitted value against the source regex. The
candidate is labelled `narrower` and carries a limitation naming what was
dropped: a request mixing encoding depths within one value.

Guards: ladders of differing lengths have no common depth to align on and
decline rather than guess; an ordinary alternation (`(?:alpha|beta|gamma)`) is
not a ladder and still expands normally; and alignment does not lift the
32-value cap.

The Python compiler was given the same treatment, and both emit identical
bytes for this rule — verified by compiling it in each and diffing the compact
JSON.

## Firewall and EDR candidates

This build translates only to Akamai, so a `firewall-generic` or `edr-s1`
candidate is a control it does not carry. That is not a malformed request, and
it does not report as one:

```json
{
  "terminal_state": "scope-declined",
  "status": "declined",
  "outcome_reason": {
    "code": "invalid-input",
    "detail": "Target technology 'firewall-generic' (firewall control class) is a valid capability target but is outside this deployment's configured coverage, which is akamai-waf. Route the firewall candidate to a deployment that carries that adapter, or regenerate it for akamai-waf."
  }
}
```

`scope-declined` is what the CFS specifies: *"valid target outside configured
coverage"*. `cannot-express` is a different question — a target that **cannot
represent the pattern** — which the adapter answers further down. Akamai is not
failing to express a firewall rule here; it was never asked.

The reason code is a known rough edge. `scope-declined` admits only
`invalid-input`, `policy-conflict`, `loop-exhausted-with-bypass` and
`bypass-found-requires-regeneration`, none of which means "outside configured
coverage", so `invalid-input` carries it and the detail does the real work.
`unsupported-target-technology` exists in the reason table under
`cannot-express`, where the CFS definition does not fit it, and is emitted by
neither service. Worth raising with whoever owns the contract.

Properties the tests hold to:

- **A decline is a result, not an error.** HTTP 200 with a typed body, never a
  4xx or 5xx.
- **The subject survives**, so the decline is attributable to a vulnerability
  and a candidate, and the requested target is echoed in `input_bindings`.
- **It is durable.** The decline is persisted like any other run and readable
  from `/runs/{id}` and `/v1/results/{id}`.
- **Async runs complete, not fail.** Nothing about an unsupported target is
  transient, so the run does not retry or sit in the queue.
- **Referenced requests keep their references.** The three rows are read and
  lineage-checked first, so `reference_bundle` and the resolved subject are
  intact.
- **The target is checked before the policy snapshot**, so the decline names
  the real reason rather than a missing fixture snapshot.

An identifier the contract does not define at all (say `palo-alto-panorama`)
gets a different message, because that is a typo or a bad binding rather than
coverage this deployment happens to lack. A control class that does not match
its target (a `waf` candidate sent to `firewall-generic`) declines the same
way: that pairing is genuinely invalid.

## What this build deliberately does not have

| Removed | Consequence |
|---|---|
| Live LLM doer | `RUN_MODE=live` **fails readiness on purpose**, rather than serving deterministic output while claiming to be live. |
| Fixture doer | An unmappable rule is `cannot-express`, not a template. |
| `firewall-generic` and `edr-s1` adapters | Those targets are `scope-declined`; see below. |
| Orchestration callbacks | The `X-Janus-Callback-*` header group is validated all-or-none, then ignored. Polling is the delivery mechanism. |
| SQLite as a *result* store | It coordinates the queue only; results go to Databricks. |
| The other three deterministic Akamai paths | JSON-body-field, anchored-literal, and proven-form-body. The rows they read from are still fetched; only those alternative compilations are gone, so a rule that used to take one of them now goes through the general compiler or declines. |

The full-parity version, before this cut, is archived at
`/private/tmp/claude-501/.../scratchpad/go-api-full-parity.tgz` — it was never
committed, so that archive is the only copy.

## Verification status

- The compiler is pinned byte-for-byte to the Python service's output
  (`TestNamedArgumentRegexMatchesPythonBytes`), because the compiled rule is
  hashed into `content_hash`. Encoding-ladder handling was ported to Python at
  the same time and was diffed byte-for-byte across both.
- The HTTP surface, the upstream reader, the result store, and the full
  asynchronous lifecycle are exercised end to end against an in-process fake
  workspace (`internal/store/storetest`) and a real temporary SQLite queue —
  including six lineage-failure cases, the approved-table check, idempotency
  and conflict, cancellation, and the attempt-exhaustion path.
- **Neither the store nor the client has been run against a live Databricks
  workspace.** The SQL and the table shape are taken from the Python service,
  but that is a code reading, not a test. Validate before deployment.

## Layout

```
cmd/api               process entry point
internal/config       environment settings
internal/contracts    request and result models
internal/terminal     terminal states, reason codes, status mapping
internal/adapters     Akamai shape validation and conflict detection
internal/policy       fixture policy snapshots
internal/translation  the ModSecurity compiler and the judge gates
internal/capability   gate order and result assembly
internal/databricks   the shared SQL Statement Execution REST client
internal/upstream     proof-loop lineage validation and the three-table read
internal/store        Databricks persistence for immutable results
internal/lifecycle    the SQLite queue behind the asynchronous routes
internal/httpapi      routes and CORS
internal/jsonx        insertion-ordered JSON, for byte parity with Python
```

`internal/jsonx` exists because the candidate artifact is serialized, hashed,
and returned as `content_ref`. Go's `encoding/json` sorts map keys and escapes
`<`, `>`, `&`; Python's `json.dumps` preserves insertion order and does
neither. Without ordered objects the two services would produce different
hashes for the same rule.
