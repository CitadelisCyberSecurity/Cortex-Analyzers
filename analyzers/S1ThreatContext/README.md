### S1ThreatContext

Looks up a [SentinelOne](https://www.sentinelone.com/) threat by its ID and returns the threat's details along with what its storyline did on the endpoint: processes, network connections, DNS lookups, file writes and registry changes. The SOC pipeline in n8n feeds the report into alert triage.

It only reads. It sends two kinds of GET request to the Management API v2.1:

- `GET /web/api/v2.1/threats?ids=<id>` for the threat, the agent and the site.
- `GET /web/api/v2.1/threats/<id>/explore/events` for the storyline events, filtered to `process,file,ip,dns,registry`, oldest first, following `nextCursor` until `max_events` is reached.

If the events endpoint returns 404, 410 or no data (for example on a tenant that has moved storyline data to the Singularity Data Lake), the analyzer still succeeds, with the threat block filled in and `Events=0`.

The analyzer comes in only one flavor.

#### Requirements

- `url` (required): console base URL, such as `https://<tenant>.sentinelone.net`. It must use `https://`.
- `api_token` (required): a **read-only** API token, from the Viewer role or a service user with view-only scope. The analyzer never calls mitigation, isolation or other write endpoints, and the token shouldn't be able to either.
- `max_events` (optional, default 50): hard cap on the total number of events returned across all lists.
- `timeout` (optional, default 30): HTTP request timeout in seconds.

The token is stored only in the Cortex analyzer config. Error reports redact it.

#### Supported data types

- `other`: a SentinelOne threat ID, digits only (for example `1234567890123456789`). Anything else is rejected before any request is made.

#### Taxonomies

The n8n pipeline reads these. Predicates are a contract: renaming one is a breaking change.

| Level | Predicate | Value | When |
|---|---|---|---|
| info | `Found` | `True` | The threat exists |
| safe | `Found` | `False` | No threat with that ID (the only taxonomy in that case) |
| malicious / suspicious / info | `Confidence` | S1 `confidenceLevel` | `malicious` and `suspicious` keep their level; anything else is `info` |
| info | `Verdict` | S1 `analystVerdict` | e.g. `undefined`, `true_positive`, `false_positive` |
| info | `Mitigation` | S1 `mitigationStatus` | e.g. `mitigated`, `not_mitigated` |
| info | `Events` | count | Events in the report (0 when the events endpoint has none) |

`Confidence`, `Verdict` and `Mitigation` are left out when S1 doesn't return the field.

#### Report

The `full` report always has the same shape:

```json
{
  "query_type": "other",
  "found": true,
  "threat": {"id": "…", "name": "…", "classification": "…", "confidence": "…", "analyst_verdict": "…",
             "mitigation_status": "…", "incident_status": "…", "storyline": "…", "file_path": "…", "sha1": "…",
             "originator_process": "…", "command_line": "…", "process_user": "…", "endpoint": "…", "os": "…", "site": "…"},
  "processes": [{"time": "…", "name": "…", "pid": "…", "parent": "…", "user": "…", "command_line": "…", "sha1": "…"}],
  "network":   [{"time": "…", "process": "…", "direction": "…", "remote_ip": "…", "remote_port": 443}],
  "dns":       [{"time": "…", "process": "…", "query": "…", "response": "…"}],
  "files":     [{"time": "…", "process": "…", "action": "create|modify|delete|rename", "path": "…", "sha1": "…"}],
  "registry":  [{"time": "…", "process": "…", "action": "…", "key": "…"}],
  "truncated": false
}
```

- All five lists are always present, as `[]` when empty. Each is sorted oldest first.
- Fields S1 doesn't return are left out. Registry events carry no `value`, because this endpoint doesn't return one.
- Strings are cut to 500 characters and command lines to 1000. `truncated` is `true` when something was cut or more events existed beyond `max_events`.
- For inbound connections, `remote_ip` and `remote_port` come from the source side.
- Other event types (scheduled tasks, logins, modules and so on) aren't requested.

#### Artifacts

None in v1.
