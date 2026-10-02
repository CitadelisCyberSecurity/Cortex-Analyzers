### __TPL_NAME__

TODO: one paragraph on what [__TPL_NAME__](TODO: service URL) is and what this analyzer looks up.

The analyzer comes in only one flavor.

#### Requirements

- `key` (required): your __TPL_NAME__ API key.
- `timeout` (optional, default 30): HTTP request timeout in seconds.

TODO: confirm `registration_required`, `subscription_required` and `free_subscription` in `__TPL_NAME__.json`.

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

Put images in `assets/` and reference them from `__TPL_NAME__.json`:

```json
"service_logo": {"path": "assets/logo.png", "caption": "logo"},
"screenshots": [{"path": "assets/report.png", "caption": "__TPL_NAME__ report"}]
```
