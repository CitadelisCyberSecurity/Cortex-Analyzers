# Creating an analyzer

New analyzers are generated from `templates/analyzer/`. The generated code is a working example against an invented API, with its own passing tests, so you start from green and change one piece at a time.

## 1. Scaffold

```bash
python utils/new-analyzer.py --name Shodan --datatypes ip,domain
```

Don't name the analyzer after a Python library it imports (for example `--name Shodan` when you use the `shodan` package): `shodan.py` would shadow the library. Name it `ShodanLookup` or similar.

Options:

| Option | Default | Notes |
|---|---|---|
| `--name` | required | Letters and digits, starting with a letter. Used as the folder, flavor name, class name (`ShodanAnalyzer`) and taxonomy namespace. |
| `--datatypes` | required | Comma-separated Cortex data types (`ip`, `domain`, `fqdn`, `url`, `hash`, `mail`, …). |
| `--author` | `Citadelis` | |
| `--version` | `1.0` | Digits and dots. |
| `--with-thehive-templates` | off | Also creates `thehive-templates/<Name>_<version>/long.html` and `short.html`. Only useful if a TheHive instance will display the reports. |

The script refuses to overwrite an existing analyzer.

## 2. Fill in the TODOs

```bash
grep -rn "TODO:" analyzers/Shodan
```

In `shodan.py`:

- `BASE_URL` and the `Authorization` header in `__init__`.
- One handler method per data type (replace `_lookup_ip`), registered in the `HANDLERS` class attribute (data type to method name). Each returns a dict with `query_type`, `found` and the API data. If you scaffolded data types other than `ip`, `test_every_declared_data_type_has_a_handler` fails until each one has a handler; this is intentional.
- `summary()`: map the response to taxonomies (see below).
- `artifacts()`: extract related observables.

Keep all HTTP inside `_request()`. It already handles timeouts, auth failures, rate limits, 404 → "not found", and other HTTP errors, with messages that end up in IRIS. `_request()` also redacts the API key from error messages. A crash in `summary()` fails the job instead of silently sending no taxonomies.

In `Shodan.json`: `description`, `service_homepage`, and the `registration_required` / `subscription_required` / `free_subscription` flags. Add extra `configurationItems` if the service needs them. In `README.md`: fill in each section.

## 3. Taxonomies are the contract with Shuffle

Shuffle reads `summary.taxonomies` from the Cortex job report to update IRIS. The rest of the report is free-form, but taxonomies must follow these rules:

- **Namespace:** always `NAMESPACE` (the analyzer name).
- **Predicates:** short Title Case strings (`Score`, `Reports`, `Found`). Renaming a predicate breaks any Shuffle workflow that matches on it, so treat it as a breaking change.
- **Levels:** `malicious` / `suspicious` / `safe` for verdicts, `info` for context.
- **Always emit at least one taxonomy** on success. "Not found" is `safe` / `Found` / `False`, not an error.

List every taxonomy in the analyzer's README.

## 4. Tests

The tests run the analyzer exactly as Cortex does: `tests/conftest.py` writes a job folder, runs the program, and returns `output/output.json`, the same JSON Shuffle receives. All HTTP is mocked with [`responses`](https://github.com/getsentry/responses), so tests need no network access or API key.

1. Call the real API once (with `curl` or `utils/analyzer-runlocal.py`) and save the response as `tests/fixtures/<something>.json`. **Remove API keys, internal hostnames and anything else sensitive** before committing.
2. Update `tests/test_shodan.py`: URLs, fixtures, and the exact expected taxonomies and artifacts. Keep the error-path tests (401, 429, 500, timeout, unsupported type, TLP), the summary-error test, the API-key redaction tests and the handler-coverage test; they test `_request()`, `report()` and the flavor config.
3. Run:

```bash
python -m venv .venv
.venv/Scripts/python -m pip install -r analyzers/Shodan/requirements.txt -r analyzers/Shodan/tests/requirements-test.txt
.venv/Scripts/python -m pytest analyzers/Shodan/tests -v
```

(On Linux/macOS, use `.venv/bin/python`.)

Assert the **full** taxonomy list, not just one item: exact assertions catch wrong or missing taxonomies.

## 5. Optional: live smoke test

```bash
mkdir -p /tmp/job/input
cat > /tmp/job/input/input.json <<'EOF'
{"data": "8.8.8.8", "dataType": "ip", "tlp": 2, "pap": 2,
 "config": {"key": "<real key>", "check_tlp": true, "max_tlp": 2}}
EOF
python analyzers/Shodan/shodan.py /tmp/job && cat /tmp/job/output/output.json
```

Or use `utils/analyzer-runlocal.py`. Never commit the job folder; it contains your key.

## 6. Open a PR

The `tests` workflow (`.github/workflows/tests.yml`) runs on every PR:

- `test (<Analyzer>)`: one job per analyzer that has a `tests/` folder, each with only that analyzer's requirements installed.
- `template-check`: tests `utils/new-analyzer.py`, then scaffolds a throwaway analyzer and runs its generated tests.
- `tests-passed`: one aggregate result.

`tests/` is excluded from the Docker image by the analyzer's `.dockerignore`.

## One-time setup: branch protection

In GitHub → Settings → Branches, add a rule for `main` (and `develop`) with "Require status checks to pass before merging" and choose **`tests-passed`**. Choose this check rather than the per-analyzer jobs, whose names change as analyzers are added.
