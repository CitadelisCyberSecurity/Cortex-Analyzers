# Analyzer Template & Scaffolding — Design

**Date:** 2026-10-02
**Status:** Approved for planning

## Goal

Make it fast and consistent to build new custom Cortex analyzers that query
external REST APIs, using `analyzers/AbuseIPDB` as the reference pattern.
Every new analyzer must ship with unit tests that run in CI.

## Context

- Analyzers run in Cortex; **DFIR IRIS** is the case-management platform and
  **Shuffle** orchestrates between them. Shuffle parses the Cortex job report
  and writes results into IRIS.
- Reports stay **free-form** per analyzer. The stable contract Shuffle relies
  on is Cortex's `summary.taxonomies` (`level` / `namespace` / `predicate` /
  `value`).
- TheHive report templates (`long.html` / `short.html`) are optional and
  generated only on request.
- CI constraints from the existing workflows:
  - `build.yml` and `publish-catalogs.yml` treat every `analyzers/*/*.json` as
    a flavor to build, publish, and add to the catalog. The skeleton therefore
    must live **outside** `analyzers/`.
  - `publish-catalogs.yml` zips the root `thehive-templates/` folder. Skeleton
    HTML templates must live **outside** it.
  - The Docker build context is the analyzer folder (`COPY . <dir>/`), so
    `tests/` must be excluded via `.dockerignore`.
  - `build.yml` validates `name` against `^[a-z0-9._-]+$` (after lowercasing)
    and `command` against `^[A-Za-z0-9 ._/-]+$`.

## Non-goals

- No shared base class or shared library across analyzers. Each analyzer
  stays self-contained (one folder = one Docker image).
- No normalized report envelope.
- No changes to `build.yml` or `publish-catalogs.yml`.
- No changes to AbuseIPDB's runtime code.

## File layout

```
templates/
└── analyzer/
    ├── __NAME__.json
    ├── __name__.py
    ├── requirements.txt
    ├── README.md
    ├── .dockerignore
    ├── assets/.gitkeep
    ├── tests/
    │   ├── conftest.py
    │   ├── test___name__.py
    │   ├── requirements-test.txt
    │   └── fixtures/sample_response.json
    └── thehive-templates/
        ├── long.html
        └── short.html

utils/new-analyzer.py
.github/workflows/tests.yml
analyzers/AbuseIPDB/tests/          (new)
analyzers/AbuseIPDB/.dockerignore   (new)
docs/creating-an-analyzer.md
README.md                           (add link to the guide)
```

## Placeholder tokens

Plain string replacement, no templating engine. Tokens use double
underscores so they never collide with Angular `{{ }}` expressions in the
TheHive templates.

| Token | Example (`--name Shodan`) | Used in |
|---|---|---|
| `__NAME__` | `Shodan` | class name, flavor `name`, `baseConfig`, taxonomy namespace, file name of the JSON |
| `__name__` | `shodan` | Python file name, `command` path, test file name |
| `__DATATYPES__` | `["ip", "domain"]` | flavor `dataTypeList` (JSON array literal) |
| `__AUTHOR__` | `Citadelis` | flavor `author` |
| `__VERSION__` | `1.0` | flavor `version` |

Path names containing tokens are renamed as well (`__NAME__.json` →
`Shodan.json`, `__name__.py` → `shodan.py`,
`test___name__.py` → `test_shodan.py`).

## Scaffolding script — `utils/new-analyzer.py`

```
python utils/new-analyzer.py --name Shodan --datatypes ip,domain \
    [--author "Citadelis"] [--version 1.0] [--with-thehive-templates] \
    [--repo-root PATH]
```

Behavior:

1. Validates `--name`: must match `^[A-Za-z][A-Za-z0-9]*$` (a valid Python
   class-name prefix that also passes the `build.yml` regex once lowercased).
2. Validates each data type against the Cortex standard list (`ip`, `domain`,
   `fqdn`, `url`, `hash`, `mail`, `filename`, `file`, `uri_path`,
   `user-agent`, `registry`, `regexp`, `other`, `autonomous-system`, `mail_subject`).
3. Fails without writing anything if `analyzers/<Name>/` exists, or, with
   `--with-thehive-templates`, if `thehive-templates/<Name>_<ver>/` exists.
4. Copies `templates/analyzer/` (excluding its `thehive-templates/` subfolder)
   to `analyzers/<Name>/`, renaming paths and replacing tokens in every text
   file.
5. With `--with-thehive-templates`, copies the skeleton's `long.html` and
   `short.html` to `thehive-templates/<Name>_<version with "." → "_">/` with
   the same token replacement.
6. Prints the created paths and next steps (fill TODOs, record a fixture, run
   `pytest`).

Defaults: `--author Citadelis`, `--version 1.0`, `--repo-root` = parent of
`utils/`. Standard library only.

## Analyzer skeleton — `__name__.py`

Structure, mirroring AbuseIPDB with common concerns pre-solved:

- Class constants: `BASE_URL`, `NAMESPACE = "__NAME__"`,
  `MALICIOUS_THRESHOLD = 75`, `SUSPICIOUS_THRESHOLD = 1`.
- `__init__`: reads `config.key` (required), `config.timeout` (default 30);
  creates a `requests.Session` with auth header and a `User-Agent`.
- `_request(method, path, **kwargs)`: the only place HTTP happens.
  - Applies the timeout.
  - `401` / `403` → `self.error("<NAME>: authentication failed — check the API key")`
  - `404` → returns `None` (not found is a valid result, not a failure)
  - `429` → `self.error("<NAME>: rate limited by the API")`
  - other non-2xx → `self.error` with status code and response body truncated
    to 500 chars
  - `requests.Timeout` / `requests.ConnectionError` → `self.error` naming the
    service
  - Returns parsed JSON on success.
- `run()`: dispatches via a dict mapping data type → handler method
  (`{"ip": self._lookup_ip}` in the skeleton); unknown types call
  `self.notSupported()`. Calls `self.report({...})`, including a
  `query_type` key so `summary()` / `artifacts()` can branch, as AbuseIPDB does.
  A `not found` result reports `{"found": False, ...}`.
- `summary(raw)`: returns `{"taxonomies": [...]}`. Uses a `_level(score)`
  helper built on the threshold constants. Always emits at least one
  taxonomy; a not-found result emits `safe` / `Found` / `False`.
- `artifacts(raw)`: returns `build_artifact(...)` entries tagged
  `[NAMESPACE]`, de-duplicated and sorted.
- `if __name__ == "__main__": __NAME__Analyzer().run()`

Every service-specific spot is marked `# TODO:`. The skeleton is a working
example against an invented API shape, so it is runnable and testable as
generated.

### Taxonomy conventions (documented in skeleton comments and guide)

- One namespace per analyzer: the analyzer name.
- Predicates are stable Title Case strings (`Score`, `Reports`, `Found`).
  Renaming a predicate is a breaking change for Shuffle workflows.
- Levels: `malicious` / `suspicious` / `safe` reflect a verdict; `info` is
  context only.
- Every successful run emits at least one taxonomy.

## Flavor definition — `__NAME__.json`

Based on AbuseIPDB's JSON, with: `name`/`baseConfig` = `__NAME__`,
`command` = `__NAME__/__name__.py`, `dataTypeList` = `__DATATYPES__`,
`license` = `AGPL-V3`, `url` = the Citadelis repo URL;
configuration items `key` (string, required) and `timeout`
(number, optional, default 30); `config` with `check_tlp: true`,
`max_tlp: 2`, `check_pap: true`, `max_pap: 2`, `auto_extract: false`;
`registration_required` / `subscription_required` / `free_subscription`
set to `true` / `true` / `true` with a README note to adjust them;
`integration_type: "external_api"`; `service_homepage` placeholder.
`service_logo` and `screenshots` are omitted (the README explains how to add
them under `assets/`).

The generated JSON must validate against `utils/flavors/flavor_schema.json`.

## TheHive templates (skeleton)

- `short.html`: identical to AbuseIPDB's taxonomy label list (generic, works
  as-is), with the `suspicious` → `label-warning` and `info` → `label-info`
  mappings added.
- `long.html`: a minimal panel showing the observable, a verdict-coloured
  heading driven by the `summary` taxonomies, a key/value table of the
  report's top-level fields, and the standard error block from AbuseIPDB's
  template. It contains `__NAME__` tokens for the title.

## Tests

### Harness — `tests/conftest.py`

Provides a `run_analyzer` fixture:

```python
def run_analyzer(data, data_type="ip", config=None, tlp=2, pap=2) -> dict
```

1. Creates a job folder under `tmp_path` with `input/input.json` containing
   `data`, `dataType`, `tlp`, `pap`, and `config` (defaults: `key="test-key"`
   merged with the flavor's `check_tlp` / `max_tlp` / `check_pap` / `max_pap`
   values).
2. Sets `sys.argv = ["<analyzer>", str(job_dir)]` via `monkeypatch`.
3. Imports the analyzer module from the parent folder and runs
   `<Class>().run()`, catching `SystemExit`.
4. Returns the parsed `output/output.json`.

The harness exercises the real `cortexutils` file I/O path, so the returned
dict is exactly what Cortex (and therefore Shuffle) receives, including
`summary` and `artifacts`.

HTTP is mocked with the `responses` library; tests use
`responses.activate` (or the `responses` fixture) so any unmocked request
fails the test.

### Generated test cases — `test___name__.py`

| Test | Expectation |
|---|---|
| happy path (fixture JSON) | `success: true`; exact expected taxonomies; expected artifacts |
| not found (404) | `success: true`; `safe` / `Found` / `False` taxonomy |
| 401 | `success: false`; `errorMessage` mentions the API key |
| 429 | `success: false`; rate-limit message |
| timeout | `success: false`; message names the service |
| unsupported data type | `success: false` |
| TLP above `max_tlp` | `success: false`; no HTTP call made |

All pass against the generated skeleton unmodified.

`tests/requirements-test.txt`: `pytest`, `responses`.

### AbuseIPDB tests

`analyzers/AbuseIPDB/tests/` uses the same harness pattern, covering:
single-IP check (score/reports taxonomies, domain/fqdn artifacts), CIDR
block check (max score / reported IPs taxonomies, ip artifacts),
whitelisted IP (`Whitelisted` + `info`-level `Reports`), and API error
(`success: false`). Fixtures follow the documented AbuseIPDB v2 response
shapes. AbuseIPDB's `requests.get` calls have no timeout and use plain
`requests`, which `responses` mocks transparently, so no code change is
needed.

## CI — `.github/workflows/tests.yml`

Triggers: `pull_request`, and `push` to `main` and `develop`. Uses the same
pinned `actions/checkout` SHA as the existing workflows, plus
`actions/setup-python`.

Jobs:

1. **discover**: outputs a JSON matrix of analyzer folder names that contain
   `tests/` (`analyzers/*/tests`). If none, the test job is skipped.
2. **test** (matrix, `fail-fast: false`): Python 3.12; installs
   `analyzers/<X>/requirements.txt` and `analyzers/<X>/tests/requirements-test.txt`;
   runs `pytest analyzers/<X>/tests -v`.
3. **template-check**:
   - runs `python utils/new-analyzer.py --name CiSmoke --datatypes ip --with-thehive-templates`
   - fails if any `__NAME__`, `__name__`, `__DATATYPES__`, `__AUTHOR__`, or
     `__VERSION__` token remains in the generated files
   - validates `analyzers/CiSmoke/CiSmoke.json` against
     `utils/flavors/flavor_schema.json` with an inline Python step using
     `jsonschema.Draft7Validator` that exits non-zero on any error
     (`check_json_schema.py` always exits 0, so it cannot gate CI; it is left
     unchanged)
   - installs requirements and runs `pytest analyzers/CiSmoke/tests`
   - generated files are never committed (CI workspace only)

Making the `test` and `template-check` jobs required status checks for
`main` / `develop` is a manual GitHub branch-protection step, documented in
the guide.

## Documentation — `docs/creating-an-analyzer.md`

1. Scaffold with `new-analyzer.py`.
2. Fill in `# TODO:` spots (base URL, auth header, handlers, summary,
   artifacts).
3. Record a real API response as `tests/fixtures/*.json` (redact secrets and
   anything sensitive), then update the tests.
4. Run tests locally (`pip install -r requirements.txt -r tests/requirements-test.txt && pytest`).
5. Optional live smoke test with `utils/analyzer-runlocal.py`.
6. Open a PR; CI must pass.
7. Taxonomy conventions and their importance for Shuffle → IRIS.
8. Branch-protection setup (one-time).

The root `README.md` gets a short "Creating a new analyzer" section linking
to the guide.

## Success criteria

- `python utils/new-analyzer.py --name Foo --datatypes ip` produces an
  analyzer whose tests pass with no edits, and whose JSON validates against
  `flavor_schema.json`.
- `tests.yml` runs the AbuseIPDB tests and the template check, and both pass.
- No `tests/` folder ends up in built images (`.dockerignore`).
- `build.yml` and `publish-catalogs.yml` are unchanged and never see the
  skeleton.
