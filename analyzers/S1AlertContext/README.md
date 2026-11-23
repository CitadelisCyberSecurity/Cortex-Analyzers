### S1AlertContext

Looks up a [SentinelOne](https://www.sentinelone.com/) Unified Alert Management (UAM) alert by its ID and returns the alert's details, assets, indicators with MITRE mapping, observables, process, Purple AI's investigation, related alerts and the source's raw alert. UAM holds alerts from every source (EDR, Identity, STAR rules, cloud and third-party integrations), and the report has the same shape for all of them. The SOC pipeline in n8n feeds it into alert triage.

#### Read-only, and why it POSTs

It only reads, but it is an exception to this repo's GET-only habit: UAM is GraphQL-only, so every request is a `POST /web/api/v2.1/unifiedalerts/graphql`. Queries and mutations share that endpoint, so the guardrails are:

- The query text is hard-coded. The alert ID goes in only as a GraphQL variable and is never put into the query text.
- Usually there is one POST, with the fixed `QUERY` (the alert and its Purple AI investigation). `alert` and `aiInvestigations` are non-null in the schema, so a Purple AI error (for example, no Purple AI license) nulls the whole response. The analyzer sends one retry, and only when the response `data` is null and every error is on `aiInvestigations`, with a second fixed query, `ALERT_ONLY_QUERY`, which asks for the alert fields only, and reports `purple_ai: {}`.
- No mutation is ever sent. A test asserts the request bodies.
- The token should be a service user with view-only permission on Unified Alerts, so it couldn't change anything even if the code tried.

Not-found detection and the null-propagation retry have only been checked against mocked responses. Both still need confirming on a real tenant.

The analyzer comes in only one flavor.

#### Requirements

- `url` (required): console base URL, such as `https://<tenant>.sentinelone.net`. It must use `https://`.
- `api_token` (required): the API token of a service user with view-only permission on Unified Alerts (RBAC). It is sent in the `Authorization: ApiToken <token>` header.
- `timeout` (optional, default 30): HTTP request timeout in seconds.

The token is stored only in the Cortex analyzer config. Error reports redact it.

#### Supported data types

- `other`: a UAM alert ID, 1 to 64 letters, digits or dashes (for example `018e1efe-6784-7c0f-893f-b8b8e740a6cd`). Anything else is rejected before any request is made.

#### Taxonomies

The n8n pipeline reads these. Predicates are a contract: renaming one is a breaking change.

| Level | Predicate | Value | When |
|---|---|---|---|
| info | `Found` | `True` | The alert exists |
| safe | `Found` | `False` | No alert with that ID (the only taxonomy in that case) |
| malicious / suspicious / info | `Confidence` | S1 `confidenceLevel` | `malicious` and `suspicious` keep their level; anything else is `info` |
| info | `Severity` | S1 `severity` | e.g. `CRITICAL`, `HIGH`, `UNKNOWN` |
| info | `Product` | `detectionSource.product` | e.g. `EDR`, `Identity`, `STAR`, `AWS` |
| info | `Status` | S1 `status` | e.g. `NEW`, `IN_PROGRESS` |
| info | `Verdict` | S1 `analystVerdict` | e.g. `UNDEFINED`, `TRUE_POSITIVE` |
| info | `PurpleAI` | Purple AI's verdict | Only when Purple AI's status is `COMPLETED`. Always `info`: its opinion never sets the alert's level |
| info | `Indicators` | count | Indicators in the report |

Every predicate except `Found` and `Indicators` is left out when S1 doesn't return the field.

#### Report

The `full` report always has the same shape:

```json
{
  "query_type": "other",
  "found": true,
  "alert": {"id": "…", "external_id": "…", "name": "…", "description": "…", "severity": "HIGH", "status": "NEW",
            "confidence": "SUSPICIOUS", "classification": "…", "analyst_verdict": "UNDEFINED", "product": "EDR",
            "vendor": "SentinelOne", "attack_surfaces": ["ENDPOINT"], "detected_at": "…", "first_seen_at": "…",
            "last_seen_at": "…", "storyline_id": "…", "link": "…"},
  "assets":       [{"name": "…", "category": "…", "subcategory": "…", "os": "…", "last_logged_in_user": "…",
                    "agent_uuid": "…", "primary": true, "tags": ["key=value"]}],
  "indicators":   [{"time": "…", "title": "…", "type": "…", "severity": "…", "description": "…",
                    "mitre": ["TA0005 Stealth / T1027 Obfuscated Files or Information"]}],
  "observables":  [{"type": "IP", "name": "…", "value": "…"}],
  "process":      {"command_line": "…", "parent": "…", "user": "DOMAIN\\user", "file_path": "…", "sha1": "…", "sha256": "…"},
  "purple_ai":    {"status": "COMPLETED", "verdict": "TRUE_POSITIVE", "result": "…", "timestamp": "…"},
  "related_alerts": [{"id": "…", "name": "…"}],
  "raw_data": "…",
  "truncated": false
}
```

- Every key is always present: lists as `[]`, objects as `{}`, `raw_data` as `""`. Fields S1 doesn't return are left out of the inner objects. When the alert isn't found, `found` is `false` and everything else is empty.
- `indicators` are sorted oldest first. `observables` merges the alert's list with each indicator's list and removes duplicates on (type, value).
- An observable's `type` falls back to `typeName` when `type` is empty.
- `purple_ai` is `{}` when Purple AI returns nothing or errors (see above).
- `raw_data` is the source's raw alert as compact JSON, cut to 8000 characters. Before it is cut, empty values and S1's own bookkeeping keys (`default_value_fields`, `s1_metadata`, `internal_uid`) are removed, so more of the source's real detail fits. When it is cut it may not be valid JSON.
- Caps: strings are cut to 500 characters, command lines to 1000 and the Purple AI result to 2000. Strings inside lists (such as asset tags) are cut the same way. At most 50 indicators, 100 observables, 20 assets, 20 tags per asset and 20 related alerts are kept. `truncated` is `true` when anything was cut or dropped.

#### Chaining with S1ThreatContext

For EDR alerts, n8n can also run S1ThreatContext to get the storyline events, using `alert.external_id` (believed to be the threat ID, not confirmed yet) or `alert.storyline_id`. Check which one works on a real EDR alert.

#### Artifacts

None in v1.
