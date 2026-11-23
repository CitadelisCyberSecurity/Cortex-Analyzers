### S1AlertContext

TODO: one paragraph on what [S1AlertContext](TODO: service URL) is and what this analyzer looks up.

The analyzer comes in only one flavor.

#### Requirements

- `key` (required): your S1AlertContext API key.
- `timeout` (optional, default 30): HTTP request timeout in seconds.

TODO: confirm `registration_required`, `subscription_required` and `free_subscription` in `S1AlertContext.json`.

#### Supported data types

TODO: list each data type and what is looked up for it.

#### Taxonomies

Shuffle reads these to update IRIS. Predicates are a contract: don't rename them once the analyzer is in use.

| Level | Predicate | Value | When |
|---|---|---|---|
| malicious / suspicious / safe | `Score` | 0–100 | TODO |
| info | `Reports` | count | TODO |
| safe | `Found` | `False` | The service has no record of the observable |

#### Artifacts

TODO: list the extracted observables (for example `domain`, `fqdn`).

#### Logo and screenshots

Put images in `assets/` and reference them from `S1AlertContext.json`:

```json
"service_logo": {"path": "assets/logo.png", "caption": "logo"},
"screenshots": [{"path": "assets/report.png", "caption": "S1AlertContext report"}]
```
