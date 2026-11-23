# S1AlertContext analyzer: design

## Why

The SOC pipeline only sees SentinelOne endpoint threats, through the threat webhook. S1's Unified Alert Management (UAM) holds alerts from every surface: EDR, Identity, STAR rules, cloud and third-party integrations such as AWS or Palo Alto. n8n is moving to a pull model on UAM. For each alert it pulls, it needs a small, stable context block to put into the IRIS alert and the Claude triage prompt, whatever the alert's source.

## Goals

- Given a UAM alert ID, return what S1 knows about that alert: headline fields, affected assets, indicators with MITRE, observables, process details, Purple AI's investigation, related alerts and the source's raw alert.
- Use the same report shape for every source, so n8n has one mapping.
- For EDR alerts, return `storyline_id` and `external_id` so n8n can also run S1ThreatContext for the full storyline.

## Non-goals

- Raw telemetry from the Singularity Data Lake. That's v2 and needs the SDL API. Each indicator's `eventSearchParams` is the query to start from.
- Replacing or changing S1ThreatContext.
- Pulling or listing alerts. n8n does that.
- `artifacts()`. n8n doesn't read them, the same as S1ThreatContext.

## Anti-goals

- Never change anything in S1: no mutations, notes, status or verdict changes, or actions.
- A report whose shape changes with the source.

## Constraints

- UAM is GraphQL only: `POST <console>/web/api/v2.1/unifiedalerts/graphql`. Queries and mutations share that endpoint, so this analyzer is an approved exception to the GET-only rule, with these guardrails:
  1. The token is a service user with **view** permission only on Unified Alerts.
  2. The code sends one hard-coded `query` document. The alert ID goes in as a GraphQL variable and is never spliced into the query text.
  3. A test asserts that every request is a POST to the GraphQL path whose body is exactly that query document, and that no body contains `mutation`.
- Repo conventions (ProxyCheck / S1ThreatContext): scaffold with `utils/new-analyzer.py`, all HTTP in `_request()`, a User-Agent, the token redacted from every error, `"token"` added to cortexutils' secret phrases, mocked HTTP and synthetic fixtures only.
- Auth header: `Authorization: ApiToken <token>`, as in S1's own curl example for this endpoint.

## Approaches considered

- **A. Alert context only (picked).** One GraphQL request for the alert and Purple AI. It works for every source, needs no SDL token, and the report is stable.
- **B. A plus SDL raw events.** The most context, but it needs SDL docs and maybe a second token, and event shapes differ by source. It can be added later without changing what A returns.
- **C. Merge with S1ThreatContext.** Rejected: S1ThreatContext works, and merging puts both report contracts at risk.

## Design

**Name:** `S1AlertContext`. **Data type:** `other`. **Observable:** the UAM alert `id`, e.g. `018e1efe-6784-7c0f-893f-b8b8e740a6cd`. Anything that isn't 1–64 characters of `[A-Za-z0-9-]` is rejected before any request.

**Config:** `url` (required, must be `https://`), `api_token` (required, view-only), `timeout` (default 30).

**One request**, with both root fields in one query document:

```graphql
query S1AlertContext($id: ID!) {
  alert(id: $id) { …fields below… }
  aiInvestigations(alertIds: [$id]) { status verdict result timestamp }
}
```

If `aiInvestigations` returns errors but `alert` came back (for example, no Purple AI license), the report still succeeds with `purple_ai: {}`.

**Not found:** if `data.alert` is null and the errors say the alert wasn't found, the job succeeds with `Found=False` / `safe` and empty lists. Any other GraphQL error fails the job, with the token redacted from the message. *(The error text for "not found" has to be checked against the real tenant.)*

### Taxonomies (namespace `S1AlertContext`, a contract with n8n)

| Predicate | Level | Value |
|---|---|---|
| `Found` | `info`; `safe` when not found | `True` / `False` |
| `Confidence` | `malicious` for MALICIOUS, `suspicious` for SUSPICIOUS, otherwise `info` | `confidenceLevel` |
| `Severity` | `info` | `severity` (CRITICAL … UNKNOWN) |
| `Product` | `info` | `detectionSource.product` (EDR, Identity, STAR, AWS …) |
| `Status` | `info` | `status` |
| `Verdict` | `info` | `analystVerdict` |
| `PurpleAI` | `malicious` for TRUE_POSITIVE, `safe` for FALSE_POSITIVE, otherwise `info` | AI verdict; only when its status is COMPLETED |
| `Indicators` | `info` | number of indicators |

A predicate is left out when its field is null. Not found emits only `Found=False`.

### `full` report

```json
{
  "query_type": "other",
  "found": true,
  "alert": {
    "id": "…", "external_id": "…", "name": "…", "description": "…",
    "severity": "HIGH", "status": "NEW", "confidence": "SUSPICIOUS", "classification": "RANSOMWARE",
    "analyst_verdict": "UNDEFINED", "product": "EDR", "vendor": "SentinelOne",
    "attack_surfaces": ["ENDPOINT"], "detected_at": "…", "first_seen_at": "…", "last_seen_at": "…",
    "storyline_id": "…", "link": "…"
  },
  "assets":       [{"name": "…", "category": "…", "subcategory": "…", "os": "…", "last_logged_in_user": "…", "agent_uuid": "…", "primary": true, "tags": ["key=value"]}],
  "indicators":   [{"time": "…", "title": "…", "type": "…", "severity": "…", "description": "…", "mitre": ["TA0005 Stealth / T1027 Obfuscated Files or Information"]}],
  "observables":  [{"type": "IP", "name": "…", "value": "…"}],
  "process":      {"command_line": "…", "parent": "…", "user": "…", "file_path": "…", "sha1": "…", "sha256": "…"},
  "purple_ai":    {"status": "COMPLETED", "verdict": "TRUE_POSITIVE", "result": "…"},
  "related_alerts": [{"id": "…", "name": "…"}],
  "raw_data": "…",
  "truncated": false
}
```

- Every key is always present: lists as `[]`, objects as `{}`, `raw_data` as `""`. Fields S1 doesn't return are left out of the inner objects.
- `observables` merges the alert-level list with each indicator's list, de-duplicated on (type, value).
- Size caps: 500 characters per string, 1000 per command line, 2000 for the Purple AI result, 4000 for `raw_data` (compact JSON, then cut), and at most 50 indicators, 100 observables, 20 assets and 20 related alerts. `truncated` is true if anything was cut.
- `indicators` are sorted by time, oldest first.

### Tests (mocked HTTP, synthetic fixtures)

- An EDR alert with Purple AI completed: taxonomies and the whole report asserted exactly.
- An AWS / third-party alert: no process, a `rawData` blob, non-endpoint assets.
- Not found gives `Found=False`.
- A Purple AI error alongside a good alert still succeeds with `purple_ai: {}`.
- A GraphQL error with no data fails, without the token in the message.
- Bad IDs (spaces, quotes, braces) are rejected with no request made.
- Caps and `truncated`.
- Read-only guard: exactly one POST per job, the body is the fixed query, the ID is only in `variables`, and no body contains `mutation`.
- The template's error-path tests: 401/403, 429, 5xx, timeout, TLP, redaction.

## Left to the builder

- Wiring it into `dev/docker-compose.yml`, adding a Dockerfile, the README.
- Exactly how the GraphQL "not found" error is detected, from a real response if one can be had. Otherwise match on a "not found" message, mark it in the code to be checked, and give it a fixture.

## n8n side (not this repo)

The pull loop calls Cortex with `{type: 'other', value: alert.id}`. For EDR alerts it also calls S1ThreatContext with `external_id` (the threat ID; check this against a real EDR alert). `enrich.js` maps `S1AlertContext` into IRIS.
