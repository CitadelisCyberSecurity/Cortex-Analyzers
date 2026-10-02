# Analyzer Template & Scaffolding Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A copy-and-fill analyzer skeleton plus a scaffolding script, with a Cortex-faithful pytest harness, AbuseIPDB tests, and a CI workflow that runs every analyzer's tests on each PR.

**Architecture:** The skeleton lives in `templates/analyzer/` (outside `analyzers/`, so `build.yml` / `publish-catalogs.yml` never see it). `utils/new-analyzer.py` copies it to `analyzers/<Name>/`, renaming paths and replacing `__TPL_*__` tokens. Each analyzer carries a generic `tests/conftest.py` that writes a Cortex job folder, runs the analyzer through real `cortexutils` I/O, and returns `output/output.json`. A new `.github/workflows/tests.yml` runs each analyzer's tests in its own job, plus the scaffolding script's tests, behind one aggregate `tests-passed` check.

**Tech Stack:** Python 3.12 (CI) / 3.x (local), `cortexutils` 2.2.x, `requests`, `pytest`, `responses`, `jsonschema`, GitHub Actions.

**Spec:** `docs/superpowers/specs/2026-10-02-analyzer-template-design.md`

---

## Background the implementer needs

- **How Cortex runs an analyzer:** it creates a job folder containing `input/input.json` (`data`, `dataType`, `tlp`, `pap`, `config`) and runs `python <program>.py <job_dir>`. `cortexutils.analyzer.Analyzer.__init__` reads that file and enforces TLP/PAP (`config.check_tlp`, `config.max_tlp`, …) **in the constructor**. `self.report(full)` writes `output/output.json` as `{"success": true, "summary": self.summary(full), "artifacts": self.artifacts(full), "operations": [], "full": full}`. `self.error(msg)` writes `{"success": false, "input": <input with config keys containing "key"/"password"/"secret" set to "REMOVED">, "errorMessage": msg}` and calls `sys.exit(1)`.
- **Gotcha:** `Analyzer.report()` silently swallows exceptions raised by `summary()` (it falls back to `{}`). This is why the tests assert the **exact** taxonomy list; a broken `summary()` would otherwise go unnoticed.
- **Gotcha:** `self.error()` raises `SystemExit`, which is *not* an `Exception`, so `except Exception` blocks in `run()` don't swallow it.
- **Token names:** `__TPL_NAME__` (e.g. `Shodan`), `__TPL_SLUG__` (`shodan`), `__TPL_DATATYPES__` (`["ip", "domain"]`), `__TPL_AUTHOR__`, `__TPL_VERSION__`. Never use bare `__name__`-style tokens: they collide with Python's `if __name__ == "__main__":`.
- **Line endings:** the repo is on Windows with `core.autocrlf`; the git CRLF warnings on commit are expected and harmless.
- **Shell:** commands below are written for Git Bash from the repo root. In PowerShell, use `.venv\Scripts\python` in place of `.venv/Scripts/python`.

## File map

| File | Responsibility |
|---|---|
| `utils/new-analyzer.py` | CLI + `scaffold()`: validate input, copy template, replace tokens |
| `utils/tests/test_new_analyzer.py` | Tests for the script and, end to end, for the template |
| `utils/tests/requirements-test.txt` | Deps for the above (includes analyzer runtime deps for the e2e test) |
| `templates/analyzer/__TPL_NAME__.json` | Flavor definition skeleton |
| `templates/analyzer/__TPL_SLUG__.py` | Analyzer skeleton (`_request`, `run`, `summary`, `artifacts`) |
| `templates/analyzer/requirements.txt` | Runtime deps |
| `templates/analyzer/README.md` | Per-analyzer README skeleton |
| `templates/analyzer/.dockerignore` | Keeps `tests/` out of images |
| `templates/analyzer/assets/.gitkeep` | Placeholder for logo/screenshots |
| `templates/analyzer/tests/conftest.py` | Generic Cortex-faithful harness (identical in every analyzer) |
| `templates/analyzer/tests/test___TPL_SLUG__.py` | 8 generated tests |
| `templates/analyzer/tests/requirements-test.txt` | `pytest`, `responses` |
| `templates/analyzer/tests/fixtures/sample_response.json` | Example API response |
| `templates/analyzer/thehive-templates/{long,short}.html` | Optional TheHive report templates |
| `analyzers/AbuseIPDB/tests/*`, `analyzers/AbuseIPDB/.dockerignore` | AbuseIPDB tests (runtime code unchanged) |
| `.github/workflows/tests.yml` | CI |
| `docs/creating-an-analyzer.md`, `README.md` | Team guide + link |

---

### Task 0: Local environment

**Files:** none (`.venv` is already in `.gitignore`)

- [ ] **Step 1: Confirm branch**

Run: `git branch --show-current`
Expected: `feature/analyzer-template`

- [ ] **Step 2: Create a virtualenv with all dev dependencies**

```bash
python -m venv .venv
.venv/Scripts/python -m pip install -q cortexutils requests pytest responses jsonschema
.venv/Scripts/python -m pip list | grep -iE "cortexutils|pytest|responses|jsonschema"
```

Expected: four lines listing `cortexutils 2.2.x`, `jsonschema`, `pytest`, `responses`.

- [ ] **Step 3: Checksum the files this plan must not change**

`analyzers/AbuseIPDB/`, the existing workflows and `thehive-templates/` are untracked in git, so record checksums now and verify them in Tasks 5 and 8:

```bash
sha256sum analyzers/AbuseIPDB/abuseipdb.py analyzers/AbuseIPDB/AbuseIPDB.json \
  .github/workflows/build.yml .github/workflows/publish-catalogs.yml \
  thehive-templates/AbuseIPDB_2_0/long.html thehive-templates/AbuseIPDB_2_0/short.html \
  > "$TEMP/protected-files.sha256"
cat "$TEMP/protected-files.sha256"
```

Expected: six checksum lines.

---

### Task 1: Scaffolding script tests (failing)

**Files:**
- Create: `utils/tests/test_new_analyzer.py`
- Create: `utils/tests/requirements-test.txt`

- [ ] **Step 1: Write `utils/tests/requirements-test.txt`**

```
pytest
jsonschema
responses
cortexutils
requests
```

(`responses`, `cortexutils`, `requests` are needed by the end-to-end test, which runs a generated analyzer's tests.)

- [ ] **Step 2: Write `utils/tests/test_new_analyzer.py`**

```python
"""Tests for utils/new-analyzer.py and the analyzer template it copies."""

import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest
from jsonschema import Draft7Validator, FormatChecker

UTILS_DIR = Path(__file__).resolve().parent.parent
SCHEMA = json.loads((UTILS_DIR / "flavors" / "flavor_schema.json").read_text(encoding="utf-8"))

_spec = importlib.util.spec_from_file_location("new_analyzer", UTILS_DIR / "new-analyzer.py")
new_analyzer = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(new_analyzer)


def make(tmp_path, name="Shodan", datatypes=("ip", "domain"), **kwargs):
    return new_analyzer.scaffold(
        name, list(datatypes), "Citadelis", kwargs.pop("version", "1.0"), tmp_path, **kwargs
    )


def all_text(root):
    return {p: p.read_text(encoding="utf-8") for p in root.rglob("*") if p.is_file()}


def test_creates_renamed_files(tmp_path):
    make(tmp_path)

    analyzer = tmp_path / "analyzers" / "Shodan"
    for rel in [
        "Shodan.json", "shodan.py", "README.md", "requirements.txt", ".dockerignore",
        "assets/.gitkeep", "tests/conftest.py", "tests/test_shodan.py",
        "tests/requirements-test.txt", "tests/fixtures/sample_response.json",
    ]:
        assert (analyzer / rel).is_file(), rel
    assert not (analyzer / "thehive-templates").exists()
    assert not (tmp_path / "thehive-templates").exists()


def test_replaces_every_token(tmp_path):
    make(tmp_path)

    for path, text in all_text(tmp_path).items():
        assert "__TPL_" not in text, path
    flavor = json.loads((tmp_path / "analyzers/Shodan/Shodan.json").read_text(encoding="utf-8"))
    assert flavor["name"] == "Shodan"
    assert flavor["baseConfig"] == "Shodan"
    assert flavor["command"] == "Shodan/shodan.py"
    assert flavor["dataTypeList"] == ["ip", "domain"]
    assert flavor["author"] == "Citadelis"
    assert flavor["version"] == "1.0"


def test_leaves_python_dunders_alone(tmp_path):
    make(tmp_path)

    source = (tmp_path / "analyzers/Shodan/shodan.py").read_text(encoding="utf-8")
    assert "class ShodanAnalyzer(Analyzer):" in source
    assert 'if __name__ == "__main__":' in source
    assert "def __init__(self):" in source


def test_generated_flavor_matches_schema(tmp_path):
    make(tmp_path)

    flavor = json.loads((tmp_path / "analyzers/Shodan/Shodan.json").read_text(encoding="utf-8"))
    errors = list(Draft7Validator(SCHEMA, format_checker=FormatChecker()).iter_errors(flavor))
    assert errors == []


def test_thehive_templates_only_with_flag(tmp_path):
    make(tmp_path, with_thehive_templates=True)

    thehive = tmp_path / "thehive-templates" / "Shodan_1_0"
    long_html = (thehive / "long.html").read_text(encoding="utf-8")
    assert (thehive / "short.html").is_file()
    assert "Shodan" in long_html
    assert "{{" in long_html  # Angular expressions survive
    assert "__TPL_" not in long_html


def test_refuses_existing_analyzer(tmp_path):
    (tmp_path / "analyzers" / "Shodan").mkdir(parents=True)

    with pytest.raises(new_analyzer.ScaffoldError, match="already exists"):
        make(tmp_path)


def test_refuses_existing_thehive_dir_without_writing_anything(tmp_path):
    (tmp_path / "thehive-templates" / "Shodan_1_0").mkdir(parents=True)

    with pytest.raises(new_analyzer.ScaffoldError, match="already exists"):
        make(tmp_path, with_thehive_templates=True)
    assert not (tmp_path / "analyzers" / "Shodan").exists()


@pytest.mark.parametrize("name", ["", "1Shodan", "my-analyzer", "My Analyzer", "Sho_dan"])
def test_rejects_invalid_names(tmp_path, name):
    with pytest.raises(new_analyzer.ScaffoldError, match="Invalid name"):
        make(tmp_path, name=name)


@pytest.mark.parametrize("version", ["", "v1", "1.0-beta"])
def test_rejects_invalid_versions(tmp_path, version):
    with pytest.raises(new_analyzer.ScaffoldError, match="Invalid version"):
        make(tmp_path, version=version)


def test_parse_datatypes():
    assert new_analyzer.parse_datatypes(" ip, domain ,") == ["ip", "domain"]
    with pytest.raises(new_analyzer.ScaffoldError, match="Unknown data type"):
        new_analyzer.parse_datatypes("ip,ipv4")
    with pytest.raises(new_analyzer.ScaffoldError, match="at least one"):
        new_analyzer.parse_datatypes(" , ")


def test_main_exit_codes(tmp_path, capsys):
    args = ["--name", "Shodan", "--datatypes", "ip", "--repo-root", str(tmp_path)]

    assert new_analyzer.main(args) == 0
    assert "analyzers/Shodan/shodan.py" in capsys.readouterr().out
    assert new_analyzer.main(args) == 1
    assert "already exists" in capsys.readouterr().err


def test_generated_analyzer_tests_pass(tmp_path):
    """End to end: the skeleton's own tests pass with no edits."""
    make(tmp_path, name="CiSmoke", datatypes=("ip",))

    result = subprocess.run(
        [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider",
         str(tmp_path / "analyzers" / "CiSmoke" / "tests")],
        capture_output=True, text=True, cwd=tmp_path,
    )
    assert result.returncode == 0, result.stdout + result.stderr
```

- [ ] **Step 3: Run to verify it fails**

Run: `.venv/Scripts/python -m pytest utils/tests -q`
Expected: collection error, `FileNotFoundError` for `utils/new-analyzer.py`.

- [ ] **Step 4: Commit**

```bash
git add utils/tests/
git commit -m "test: add failing tests for new-analyzer scaffolding script"
```

---

### Task 2: Scaffolding script + static template files

**Files:**
- Create: `utils/new-analyzer.py`
- Create: `templates/analyzer/__TPL_NAME__.json`
- Create: `templates/analyzer/requirements.txt`
- Create: `templates/analyzer/.dockerignore`
- Create: `templates/analyzer/assets/.gitkeep` (empty)
- Create: `templates/analyzer/README.md`
- Create: `templates/analyzer/thehive-templates/short.html`
- Create: `templates/analyzer/thehive-templates/long.html`

- [ ] **Step 1: Write `utils/new-analyzer.py`**

```python
#!/usr/bin/env python3
"""Create a new analyzer from templates/analyzer.

Usage:
    python utils/new-analyzer.py --name Shodan --datatypes ip,domain
    python utils/new-analyzer.py --name Shodan --datatypes ip --with-thehive-templates

Copies the skeleton to analyzers/<Name>/, renames files and replaces the
__TPL_*__ tokens. Standard library only.
"""

import argparse
import json
import re
import sys
from pathlib import Path

TEMPLATE_DIR = Path(__file__).resolve().parent.parent / "templates" / "analyzer"
THEHIVE_SUBDIR = "thehive-templates"
IGNORED_NAMES = {"__pycache__", ".pytest_cache"}

NAME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9]*$")
VERSION_RE = re.compile(r"^[0-9]+(\.[0-9]+)*$")
DATATYPES = {
    "autonomous-system", "domain", "file", "filename", "fqdn", "hash", "ip",
    "mail", "mail_subject", "other", "regexp", "registry", "uri_path", "url",
    "user-agent",
}


class ScaffoldError(Exception):
    pass


def validate_name(name):
    if not NAME_RE.match(name or ""):
        raise ScaffoldError(
            f"Invalid name {name!r}: use letters and digits only, starting with a letter"
        )
    return name


def parse_datatypes(value):
    datatypes = [d.strip() for d in value.split(",") if d.strip()]
    if not datatypes:
        raise ScaffoldError("Give at least one data type")
    unknown = sorted(set(datatypes) - DATATYPES)
    if unknown:
        raise ScaffoldError(
            f"Unknown data type(s) {', '.join(unknown)}; valid: {', '.join(sorted(DATATYPES))}"
        )
    return datatypes


def validate_version(version):
    if not VERSION_RE.match(version or ""):
        raise ScaffoldError(f"Invalid version {version!r}: use digits and dots, e.g. 1.0")
    return version


def _tokens(name, datatypes, author, version):
    return {
        "__TPL_NAME__": name,
        "__TPL_SLUG__": name.lower(),
        "__TPL_DATATYPES__": json.dumps(datatypes),
        "__TPL_AUTHOR__": author,
        "__TPL_VERSION__": version,
    }


def _replace(text, tokens):
    for token, value in tokens.items():
        text = text.replace(token, value)
    return text


def _copy_tree(src_dir, dst_dir, tokens, skip=()):
    created = []
    for src in sorted(src_dir.rglob("*")):
        rel = src.relative_to(src_dir)
        if rel.parts[0] in skip or IGNORED_NAMES & set(rel.parts) or src.is_dir():
            continue
        dst = dst_dir / _replace(str(rel), tokens)
        dst.parent.mkdir(parents=True, exist_ok=True)
        dst.write_bytes(_replace(src.read_text(encoding="utf-8"), tokens).encode("utf-8"))
        created.append(dst)
    return created


def scaffold(name, datatypes, author, version, repo_root, with_thehive_templates=False):
    """Create the analyzer and return the list of files written."""
    validate_name(name)
    validate_version(version)
    repo_root = Path(repo_root)
    analyzer_dir = repo_root / "analyzers" / name
    thehive_dir = repo_root / "thehive-templates" / f"{name}_{version.replace('.', '_')}"

    # Check every destination before writing anything.
    if analyzer_dir.exists():
        raise ScaffoldError(f"{analyzer_dir} already exists")
    if with_thehive_templates and thehive_dir.exists():
        raise ScaffoldError(f"{thehive_dir} already exists")

    tokens = _tokens(name, datatypes, author, version)
    created = _copy_tree(TEMPLATE_DIR, analyzer_dir, tokens, skip={THEHIVE_SUBDIR})
    if with_thehive_templates:
        created += _copy_tree(TEMPLATE_DIR / THEHIVE_SUBDIR, thehive_dir, tokens)
    return created


def main(argv=None):
    parser = argparse.ArgumentParser(description="Create a new analyzer from templates/analyzer.")
    parser.add_argument("--name", required=True, help="Analyzer name, e.g. Shodan")
    parser.add_argument("--datatypes", required=True, help="Comma-separated, e.g. ip,domain")
    parser.add_argument("--author", default="Citadelis")
    parser.add_argument("--version", default="1.0")
    parser.add_argument("--with-thehive-templates", action="store_true",
                        help="Also create thehive-templates/<Name>_<version>/")
    parser.add_argument("--repo-root", default=str(Path(__file__).resolve().parent.parent),
                        help="Repository to create the analyzer in (default: this repo)")
    args = parser.parse_args(argv)

    try:
        datatypes = parse_datatypes(args.datatypes)
        created = scaffold(args.name, datatypes, args.author, args.version,
                           args.repo_root, args.with_thehive_templates)
    except ScaffoldError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1

    root = Path(args.repo_root)
    print(f"Created {len(created)} files:")
    for path in created:
        print(f"  {path.relative_to(root).as_posix()}")
    print(
        "\nNext steps:\n"
        "  1. Fill in every TODO: in the new files\n"
        "  2. Record a real API response into tests/fixtures/ and update the tests\n"
        f"  3. pip install -r analyzers/{args.name}/requirements.txt "
        f"-r analyzers/{args.name}/tests/requirements-test.txt\n"
        f"  4. pytest analyzers/{args.name}/tests\n"
        "See docs/creating-an-analyzer.md for details."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
```


- [ ] **Step 2: Write `templates/analyzer/__TPL_NAME__.json`**

(Not valid JSON until tokens are replaced. That's expected: `__TPL_DATATYPES__` becomes a JSON array.)

```json
{
    "name": "__TPL_NAME__",
    "version": "__TPL_VERSION__",
    "author": "__TPL_AUTHOR__",
    "url": "https://github.com/CitadelisCyberSecurity/Cortex-Analyzers",
    "license": "AGPL-V3",
    "description": "TODO: one sentence describing what __TPL_NAME__ returns.",
    "dataTypeList": __TPL_DATATYPES__,
    "baseConfig": "__TPL_NAME__",
    "command": "__TPL_NAME__/__TPL_SLUG__.py",
    "configurationItems": [
        {
            "name": "key",
            "description": "API key for __TPL_NAME__",
            "type": "string",
            "multi": false,
            "required": true
        },
        {
            "name": "timeout",
            "description": "HTTP request timeout in seconds",
            "type": "number",
            "multi": false,
            "required": false,
            "defaultValue": 30
        }
    ],
    "config": {
        "check_tlp": true,
        "max_tlp": 2,
        "check_pap": true,
        "max_pap": 2,
        "auto_extract": false
    },
    "registration_required": true,
    "subscription_required": true,
    "free_subscription": true,
    "integration_type": "external_api",
    "service_homepage": "TODO: https://www.example.com/"
}
```

- [ ] **Step 3: Write the small files**

`templates/analyzer/requirements.txt`:
```
cortexutils
requests
```

`templates/analyzer/.dockerignore`:
```
tests/
**/__pycache__/
**/*.pyc
.pytest_cache/
```

`templates/analyzer/assets/.gitkeep`: empty file.

- [ ] **Step 4: Write `templates/analyzer/README.md`**

```markdown
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

Put images in `assets/` and reference them from `__TPL_NAME__.json` with `service_logo` and `screenshots`, as `analyzers/AbuseIPDB/AbuseIPDB.json` does.
```

- [ ] **Step 5: Write `templates/analyzer/thehive-templates/short.html`**

```html
<span class="label" ng-repeat="t in content.taxonomies"
      ng-class="{'info': 'label-info', 'safe': 'label-success', 'suspicious': 'label-warning', 'malicious': 'label-danger'}[t.level]">
    {{t.namespace}}:{{t.predicate}}="{{t.value}}"
</span>
```

- [ ] **Step 6: Write `templates/analyzer/thehive-templates/long.html`**

```html
<!-- __TPL_NAME__ long report. "content" is the analyzer's full report. TODO: show the fields that matter. -->
<div class="panel panel-info" ng-if="success">
    <div class="panel-heading">
        __TPL_NAME__ report for <strong>{{(artifact.data || artifact.attachment.name) | fang}}</strong>
    </div>
    <div class="panel-body">
        <p ng-if="!content.found">No record found in __TPL_NAME__.</p>
        <dl class="dl-horizontal" ng-if="content.found">
            <dt ng-repeat-start="(field, value) in content.data">{{field}}</dt>
            <dd ng-repeat-end>{{value}}</dd>
        </dl>
    </div>
</div>

<div class="panel panel-danger" ng-if="!success">
    <div class="panel-heading">
        <strong>{{(artifact.data || artifact.attachment.name) | fang}}</strong>
    </div>
    <div class="panel-body">
        <dl class="dl-horizontal" ng-if="content && content.errorMessage">
            <dt><i class="fa fa-warning"></i> __TPL_NAME__:</dt>
            <dd class="wrap">{{content.errorMessage}}</dd>
        </dl>
    </div>
</div>
```

- [ ] **Step 7: Run tests: everything except the Python-file and end-to-end tests passes**

Run: `.venv/Scripts/python -m pytest utils/tests -q`
Expected: **4 failed, 14 passed**. Failures:
- `test_creates_renamed_files` (`shodan.py` missing)
- `test_leaves_python_dunders_alone` (`shodan.py` missing)
- `test_main_exit_codes` (output doesn't list `shodan.py` yet)
- `test_generated_analyzer_tests_pass` (no tests generated)

- [ ] **Step 8: Commit**

```bash
git add utils/new-analyzer.py templates/
git commit -m "feat: add new-analyzer scaffolding script and static template files"
```

---

### Task 3: Template test harness and generated tests

**Files:**
- Create: `templates/analyzer/tests/conftest.py`
- Create: `templates/analyzer/tests/test___TPL_SLUG__.py`
- Create: `templates/analyzer/tests/requirements-test.txt`
- Create: `templates/analyzer/tests/fixtures/sample_response.json`

- [ ] **Step 1: Write `templates/analyzer/tests/conftest.py`**

This file has no tokens. It's generic and is copied unchanged into AbuseIPDB in Task 5.

```python
"""Test harness: runs the analyzer the way Cortex does.

Each run writes a Cortex job folder (input/input.json), points sys.argv at
it, runs the analyzer, and returns output/output.json. That output is exactly
the report Cortex hands to Shuffle, including "summary" and "artifacts".

This file is generic. It finds the analyzer through the flavor JSON's
"command" field, so it can be copied unchanged into any analyzer folder.
"""

import importlib.util
import inspect
import json
import sys
import tempfile
from pathlib import Path

import pytest
import responses
from cortexutils.analyzer import Analyzer

ANALYZER_DIR = Path(__file__).resolve().parent.parent
FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"


def _load_flavor():
    flavors = sorted(ANALYZER_DIR.glob("*.json"))
    if not flavors:
        raise RuntimeError(f"No flavor JSON found in {ANALYZER_DIR}")
    # Folders with several flavors share one program; the first is enough.
    return json.loads(flavors[0].read_text(encoding="utf-8"))


def _load_analyzer_class(module_path):
    spec = importlib.util.spec_from_file_location(module_path.stem, module_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    for _, obj in inspect.getmembers(module, inspect.isclass):
        if issubclass(obj, Analyzer) and obj.__module__ == module.__name__:
            return obj
    raise RuntimeError(f"No Analyzer subclass found in {module_path}")


FLAVOR = _load_flavor()
MODULE_PATH = ANALYZER_DIR / Path(FLAVOR["command"]).name
ANALYZER_CLASS = _load_analyzer_class(MODULE_PATH)


def _default_config():
    """Config as Cortex sends it: the flavor's "config" block plus defaults."""
    config = dict(FLAVOR.get("config", {}))
    for item in FLAVOR.get("configurationItems", []):
        if "defaultValue" in item:
            config[item["name"]] = item["defaultValue"]
    config["key"] = "test-key"
    return config


@pytest.fixture
def analyzer_class():
    return ANALYZER_CLASS


@pytest.fixture
def run_analyzer(tmp_path, monkeypatch):
    def _run(data, data_type="ip", config=None, tlp=2, pap=2):
        job_config = _default_config()
        job_config.update(config or {})
        job_dir = Path(tempfile.mkdtemp(dir=tmp_path))
        (job_dir / "input").mkdir()
        job = {
            "data": data,
            "dataType": data_type,
            "tlp": tlp,
            "pap": pap,
            "config": job_config,
        }
        (job_dir / "input" / "input.json").write_text(json.dumps(job), encoding="utf-8")
        monkeypatch.setattr(sys, "argv", [str(MODULE_PATH), str(job_dir)])
        try:
            ANALYZER_CLASS().run()
        except SystemExit:
            pass  # self.error() exits after writing the error report
        return json.loads((job_dir / "output" / "output.json").read_text(encoding="utf-8"))

    return _run


@pytest.fixture
def mocked_api():
    """Mocks all HTTP. Unregistered calls fail; unused registrations fail too."""
    with responses.RequestsMock(assert_all_requests_are_fired=True) as rsps:
        yield rsps


@pytest.fixture
def load_fixture():
    def _load(name):
        return json.loads((FIXTURES_DIR / name).read_text(encoding="utf-8"))

    return _load
```

- [ ] **Step 2: Write `templates/analyzer/tests/requirements-test.txt`**

```
pytest
responses
```

- [ ] **Step 3: Write `templates/analyzer/tests/fixtures/sample_response.json`**

The mixed case, trailing dots and duplicate hostname are deliberate: they exercise normalisation and de-duplication in `artifacts()`.

```json
{
    "ip": "198.51.100.7",
    "score": 87,
    "reports": 412,
    "domain": "Example-Hosting.net.",
    "hostnames": [
        "scanner01.example-hosting.net",
        "SCANNER01.example-hosting.net."
    ]
}
```

- [ ] **Step 4: Write `templates/analyzer/tests/test___TPL_SLUG__.py`**

```python
"""Tests for the __TPL_NAME__ analyzer.

They run the analyzer exactly as Cortex does (see conftest.py) with all HTTP
mocked, so no network access or API key is needed. When you replace the
example API logic, record a real response into tests/fixtures/ and update
these tests to match.
"""

import requests

IP = "198.51.100.7"
NS = "__TPL_NAME__"


def ip_url(analyzer_class):
    return f"{analyzer_class.BASE_URL}/ip/{IP}"


def test_found_reports_taxonomies_and_artifacts(run_analyzer, mocked_api, analyzer_class, load_fixture):
    mocked_api.get(ip_url(analyzer_class), json=load_fixture("sample_response.json"))

    output = run_analyzer(IP)

    assert output["success"] is True
    assert output["summary"]["taxonomies"] == [
        {"level": "malicious", "namespace": NS, "predicate": "Score", "value": 87},
        {"level": "info", "namespace": NS, "predicate": "Reports", "value": 412},
    ]
    assert output["artifacts"] == [
        {"dataType": "domain", "data": "example-hosting.net", "tags": [NS]},
        {"dataType": "fqdn", "data": "scanner01.example-hosting.net", "tags": [NS]},
    ]
    assert output["full"]["found"] is True
    assert mocked_api.calls[0].request.headers["Authorization"] == "Bearer test-key"


def test_not_found_is_a_safe_result(run_analyzer, mocked_api, analyzer_class):
    mocked_api.get(ip_url(analyzer_class), status=404)

    output = run_analyzer(IP)

    assert output["success"] is True
    assert output["summary"]["taxonomies"] == [
        {"level": "safe", "namespace": NS, "predicate": "Found", "value": "False"},
    ]
    assert output["artifacts"] == []


def test_auth_failure_mentions_api_key_and_hides_it(run_analyzer, mocked_api, analyzer_class):
    mocked_api.get(ip_url(analyzer_class), status=401)

    output = run_analyzer(IP)

    assert output["success"] is False
    assert "API key" in output["errorMessage"]
    assert output["input"]["config"]["key"] == "REMOVED"


def test_rate_limit_is_reported(run_analyzer, mocked_api, analyzer_class):
    mocked_api.get(ip_url(analyzer_class), status=429)

    output = run_analyzer(IP)

    assert output["success"] is False
    assert "rate limited" in output["errorMessage"]


def test_server_error_includes_status_and_body(run_analyzer, mocked_api, analyzer_class):
    mocked_api.get(ip_url(analyzer_class), status=500, body="upstream exploded")

    output = run_analyzer(IP)

    assert output["success"] is False
    assert "HTTP 500" in output["errorMessage"]
    assert "upstream exploded" in output["errorMessage"]


def test_timeout_names_the_service(run_analyzer, mocked_api, analyzer_class):
    mocked_api.get(ip_url(analyzer_class), body=requests.exceptions.ReadTimeout())

    output = run_analyzer(IP)

    assert output["success"] is False
    assert output["errorMessage"].startswith(f"{NS}: request timed out")


def test_unsupported_data_type(run_analyzer, mocked_api):
    output = run_analyzer("user@example.com", data_type="mail")

    assert output["success"] is False
    assert "not supported" in output["errorMessage"]


def test_tlp_above_max_is_rejected_before_any_request(run_analyzer, mocked_api):
    output = run_analyzer(IP, tlp=3)

    assert output["success"] is False
    assert "TLP" in output["errorMessage"]
    assert len(mocked_api.calls) == 0
```

- [ ] **Step 5: Run: the end-to-end test now fails for the right reason**

Run: `.venv/Scripts/python -m pytest utils/tests -q`
Expected: **4 failed, 14 passed** (same four as Task 2). The `test_generated_analyzer_tests_pass` output should now show the generated `conftest.py` failing to load `cismoke.py` (`FileNotFoundError` / `No such file`), which confirms the harness runs.

- [ ] **Step 6: Commit**

```bash
git add templates/analyzer/tests/
git commit -m "test: add Cortex-faithful harness and generated tests to analyzer template"
```

---

### Task 4: Template analyzer program

**Files:**
- Create: `templates/analyzer/__TPL_SLUG__.py`

- [ ] **Step 1: Write `templates/analyzer/__TPL_SLUG__.py`**

```python
#!/usr/bin/env python3
"""__TPL_NAME__ analyzer for Cortex.

Generated from templates/analyzer. Every spot that needs service-specific
code is marked "TODO:". See docs/creating-an-analyzer.md.

API docs: TODO: link to the service's API documentation.
"""

import requests
from cortexutils.analyzer import Analyzer


class __TPL_NAME__Analyzer(Analyzer):
    # TODO: set the service's API base URL.
    BASE_URL = "https://api.example.com/v1"
    # Taxonomy namespace. Shuffle workflows match on it: don't rename it once
    # the analyzer is in use.
    NAMESPACE = "__TPL_NAME__"
    USER_AGENT = "citadelis-cortex-__TPL_SLUG__/__TPL_VERSION__"

    # Score thresholds used by _level(). TODO: adjust to the service's scale.
    MALICIOUS_THRESHOLD = 75
    SUSPICIOUS_THRESHOLD = 1

    def __init__(self):
        super().__init__()
        self.api_key = self.get_param("config.key", None, "Missing API key")
        self.timeout = self.get_param("config.timeout", 30)
        self.session = requests.Session()
        self.session.headers.update(
            {
                "Accept": "application/json",
                "User-Agent": self.USER_AGENT,
                # TODO: use the auth scheme the service expects.
                "Authorization": f"Bearer {self.api_key}",
            }
        )

    def _request(self, method, path, **kwargs):
        """Send one API request and return the parsed JSON body.

        Returns None on 404: "not found" is a valid answer, not a failure.
        Any other failure ends the job through self.error(), which writes the
        error report and exits.
        """
        url = f"{self.BASE_URL}{path}"
        try:
            response = self.session.request(method, url, timeout=self.timeout, **kwargs)
        except requests.exceptions.Timeout:
            self.error(f"{self.NAMESPACE}: request timed out after {self.timeout}s")
        except requests.exceptions.RequestException as e:
            self.error(f"{self.NAMESPACE}: could not reach the API ({e})")

        if response.status_code == 404:
            return None
        if response.status_code in (401, 403):
            self.error(f"{self.NAMESPACE}: authentication failed, check the API key")
        if response.status_code == 429:
            self.error(f"{self.NAMESPACE}: rate limited by the API, try again later")
        if not response.ok:
            self.error(
                f"{self.NAMESPACE}: API returned HTTP {response.status_code}: "
                f"{response.text[:500]}"
            )
        try:
            return response.json()
        except ValueError:
            self.error(f"{self.NAMESPACE}: API returned a response that is not JSON")

    def _lookup_ip(self, ip):
        # TODO: call the service's real endpoint for this data type.
        data = self._request("GET", f"/ip/{ip}")
        return {"query_type": "ip", "found": data is not None, "data": data}

    def run(self):
        try:
            handlers = {
                "ip": self._lookup_ip,
                # TODO: add one handler per data type in the flavor's dataTypeList.
            }
            handler = handlers.get(self.data_type)
            if handler is None:
                self.notSupported()
            self.report(handler(self.get_data()))
        except Exception as e:
            self.unexpectedError(e)

    def _level(self, score):
        if score >= self.MALICIOUS_THRESHOLD:
            return "malicious"
        if score >= self.SUSPICIOUS_THRESHOLD:
            return "suspicious"
        return "safe"

    def summary(self, raw):
        """Taxonomies are the stable contract Shuffle parses.

        Rules: one namespace (NAMESPACE), Title Case predicates that never get
        renamed, malicious/suspicious/safe for verdicts and info for context,
        and at least one taxonomy on every successful run.
        """
        if not raw.get("found"):
            return {"taxonomies": [self.build_taxonomy("safe", self.NAMESPACE, "Found", "False")]}

        data = raw.get("data") or {}
        taxonomies = []
        # TODO: map the service's fields to taxonomies.
        score = data.get("score")
        if score is not None:
            taxonomies.append(
                self.build_taxonomy(self._level(score), self.NAMESPACE, "Score", score)
            )
        reports = data.get("reports")
        if reports is not None:
            taxonomies.append(self.build_taxonomy("info", self.NAMESPACE, "Reports", reports))
        if not taxonomies:
            taxonomies.append(self.build_taxonomy("info", self.NAMESPACE, "Found", "True"))
        return {"taxonomies": taxonomies}

    def artifacts(self, raw):
        data = raw.get("data") or {}
        found = set()
        # TODO: extract the related observables the service returns.
        domain = (data.get("domain") or "").strip().rstrip(".").lower()
        if domain:
            found.add(("domain", domain))
        for hostname in data.get("hostnames") or []:
            hostname = (hostname or "").strip().rstrip(".").lower()
            if hostname:
                found.add(("fqdn", hostname))
        return [
            self.build_artifact(data_type, value, tags=[self.NAMESPACE])
            for data_type, value in sorted(found)
        ]


if __name__ == "__main__":
    __TPL_NAME__Analyzer().run()
```

- [ ] **Step 2: Run all script tests**

Run: `.venv/Scripts/python -m pytest utils/tests -q`
Expected: `18 passed`.

- [ ] **Step 3: Check the generated analyzer by hand**

```bash
python utils/new-analyzer.py --name Demo --datatypes ip --with-thehive-templates
.venv/Scripts/python -m pytest analyzers/Demo/tests -v
```

Expected: the script lists 12 created files (10 under `analyzers/Demo/`, 2 under `thehive-templates/Demo_1_0/`), then `8 passed`.

Then **delete the demo output so it isn't committed**:

```bash
rm -rf analyzers/Demo thehive-templates/Demo_1_0
git status --short   # must not list analyzers/Demo or thehive-templates/Demo_1_0
```

- [ ] **Step 4: Commit**

```bash
git add templates/analyzer/__TPL_SLUG__.py
git commit -m "feat: add analyzer program skeleton to template"
```

---

### Task 5: AbuseIPDB tests

AbuseIPDB's runtime code (`abuseipdb.py`, `AbuseIPDB.json`) must **not** change.

**Files:**
- Create: `analyzers/AbuseIPDB/.dockerignore` (copy of the template's)
- Create: `analyzers/AbuseIPDB/tests/conftest.py` (copy of the template's)
- Create: `analyzers/AbuseIPDB/tests/requirements-test.txt` (copy of the template's)
- Create: `analyzers/AbuseIPDB/tests/fixtures/check_tor_exit.json`
- Create: `analyzers/AbuseIPDB/tests/fixtures/check_whitelisted.json`
- Create: `analyzers/AbuseIPDB/tests/fixtures/check_block.json`
- Create: `analyzers/AbuseIPDB/tests/test_abuseipdb.py`

- [ ] **Step 1: Copy the generic files**

```bash
mkdir -p analyzers/AbuseIPDB/tests/fixtures
cp templates/analyzer/.dockerignore analyzers/AbuseIPDB/
cp templates/analyzer/tests/conftest.py templates/analyzer/tests/requirements-test.txt analyzers/AbuseIPDB/tests/
```

- [ ] **Step 2: Write `analyzers/AbuseIPDB/tests/fixtures/check_tor_exit.json`**

```json
{
    "data": {
        "ipAddress": "185.220.101.1",
        "isPublic": true,
        "ipVersion": 4,
        "isWhitelisted": false,
        "abuseConfidenceScore": 100,
        "countryCode": "DE",
        "countryName": "Germany",
        "usageType": "Data Center/Web Hosting/Transit",
        "isp": "Example Hosting GmbH",
        "domain": "Example-Hosting.de",
        "hostnames": ["tor-exit-1.example-hosting.de."],
        "isTor": true,
        "totalReports": 2,
        "numDistinctUsers": 2,
        "lastReportedAt": "2026-09-30T10:00:00+00:00",
        "reports": [
            {
                "reportedAt": "2026-09-30T10:00:00+00:00",
                "comment": "SSH brute force",
                "categories": [18, 22],
                "reporterId": 1001,
                "reporterCountryCode": "US",
                "reporterCountryName": "United States"
            },
            {
                "reportedAt": "2026-09-29T08:30:00+00:00",
                "comment": "Port scan",
                "categories": [14],
                "reporterId": 1002,
                "reporterCountryCode": "FR",
                "reporterCountryName": "France"
            }
        ]
    }
}
```

- [ ] **Step 3: Write `analyzers/AbuseIPDB/tests/fixtures/check_whitelisted.json`**

```json
{
    "data": {
        "ipAddress": "8.8.8.8",
        "isPublic": true,
        "ipVersion": 4,
        "isWhitelisted": true,
        "abuseConfidenceScore": 0,
        "countryCode": "US",
        "isp": "Google LLC",
        "domain": "google.com",
        "hostnames": ["dns.google"],
        "isTor": false,
        "totalReports": 3,
        "numDistinctUsers": 3,
        "lastReportedAt": "2026-09-01T12:00:00+00:00",
        "reports": []
    }
}
```

- [ ] **Step 4: Write `analyzers/AbuseIPDB/tests/fixtures/check_block.json`**

```json
{
    "data": {
        "networkAddress": "192.0.2.0",
        "netmask": "255.255.255.0",
        "minAddress": "192.0.2.1",
        "maxAddress": "192.0.2.254",
        "numPossibleHosts": 254,
        "addressSpaceDesc": "Internet",
        "reportedAddress": [
            {
                "ipAddress": "192.0.2.20",
                "numReports": 1,
                "mostRecentReport": "2026-09-28T09:00:00+00:00",
                "abuseConfidenceScore": 10,
                "countryCode": "FR"
            },
            {
                "ipAddress": "192.0.2.10",
                "numReports": 5,
                "mostRecentReport": "2026-09-30T10:00:00+00:00",
                "abuseConfidenceScore": 80,
                "countryCode": "US"
            }
        ]
    }
}
```

- [ ] **Step 5: Write `analyzers/AbuseIPDB/tests/test_abuseipdb.py`**

These are characterisation tests: they lock in the existing behaviour of `abuseipdb.py`, so they should pass on the first run. To confirm they really check something, Step 7 breaks one on purpose.

```python
"""Tests for the AbuseIPDB analyzer.

Fixtures follow the AbuseIPDB APIv2 response shapes
(https://docs.abuseipdb.com/). All HTTP is mocked; see conftest.py.
"""

from responses import matchers

CHECK_URL = "https://api.abuseipdb.com/api/v2/check"
BLOCK_URL = "https://api.abuseipdb.com/api/v2/check-block"
NS = "AbuseIPDB"


def test_single_ip_check(run_analyzer, mocked_api, load_fixture):
    mocked_api.get(
        CHECK_URL,
        json=load_fixture("check_tor_exit.json"),
        match=[
            matchers.query_param_matcher(
                {"maxAgeInDays": "30", "verbose": "True", "ipAddress": "185.220.101.1"}
            ),
            matchers.header_matcher({"Key": "test-key"}),
        ],
    )

    output = run_analyzer("185.220.101.1")

    assert output["success"] is True
    assert output["summary"]["taxonomies"] == [
        {"level": "info", "namespace": NS, "predicate": "Tor", "value": "True"},
        {"level": "info", "namespace": NS, "predicate": "Usage", "value": "Data Center/Web Hosting/Transit"},
        {"level": "malicious", "namespace": NS, "predicate": "Score", "value": 100},
        {"level": "malicious", "namespace": NS, "predicate": "Reports", "value": 2},
    ]
    assert output["artifacts"] == [
        {"dataType": "domain", "data": "example-hosting.de", "tags": [NS]},
        {"dataType": "fqdn", "data": "tor-exit-1.example-hosting.de", "tags": [NS]},
    ]
    report = output["full"]
    assert report["query_type"] == "check"
    assert report["values"][0]["categories_strings"] == ["Brute Force", "SSH", "Port Scan"]


def test_days_config_is_sent(run_analyzer, mocked_api, load_fixture):
    mocked_api.get(
        CHECK_URL,
        json=load_fixture("check_tor_exit.json"),
        match=[matchers.query_param_matcher(
            {"maxAgeInDays": "90", "verbose": "True", "ipAddress": "185.220.101.1"}
        )],
    )

    output = run_analyzer("185.220.101.1", config={"days": 90})

    assert output["success"] is True


def test_whitelisted_ip_reports_are_info(run_analyzer, mocked_api, load_fixture):
    mocked_api.get(CHECK_URL, json=load_fixture("check_whitelisted.json"))

    output = run_analyzer("8.8.8.8")

    assert output["success"] is True
    assert output["summary"]["taxonomies"] == [
        {"level": "info", "namespace": NS, "predicate": "Whitelisted", "value": "True"},
        {"level": "safe", "namespace": NS, "predicate": "Score", "value": 0},
        {"level": "info", "namespace": NS, "predicate": "Reports", "value": 3},
    ]


def test_cidr_block_check(run_analyzer, mocked_api, load_fixture):
    mocked_api.get(
        BLOCK_URL,
        json=load_fixture("check_block.json"),
        match=[matchers.query_param_matcher({"maxAgeInDays": "30", "network": "192.0.2.0/24"})],
    )

    output = run_analyzer("192.0.2.0/24")

    assert output["success"] is True
    assert output["summary"]["taxonomies"] == [
        {"level": "malicious", "namespace": NS, "predicate": "Max Score", "value": 80},
        {"level": "suspicious", "namespace": NS, "predicate": "Reported IPs", "value": 2},
        {"level": "info", "namespace": NS, "predicate": "Total Reports", "value": 6},
    ]
    assert output["artifacts"] == [
        {"dataType": "ip", "data": "192.0.2.10", "tags": [NS]},
        {"dataType": "ip", "data": "192.0.2.20", "tags": [NS]},
    ]
    assert output["full"]["query_type"] == "check-block"


def test_api_error(run_analyzer, mocked_api):
    mocked_api.get(CHECK_URL, status=401, json={"errors": [{"detail": "Authentication failed."}]})

    output = run_analyzer("185.220.101.1")

    assert output["success"] is False
    assert output["errorMessage"].startswith("Unable to query AbuseIPDB API")
    assert "Authentication failed." in output["errorMessage"]
    assert output["input"]["config"]["key"] == "REMOVED"


def test_tlp_above_max_is_rejected(run_analyzer, mocked_api):
    output = run_analyzer("185.220.101.1", tlp=3)

    assert output["success"] is False
    assert "TLP" in output["errorMessage"]
    assert len(mocked_api.calls) == 0
```

- [ ] **Step 6: Run**

Run: `.venv/Scripts/python -m pytest analyzers/AbuseIPDB/tests -v`
Expected: `6 passed`.

- [ ] **Step 7: Confirm the tests can fail**

Temporarily change `"value": 100` to `"value": 99` in `test_single_ip_check`, re-run, and confirm it FAILS with a taxonomy diff. Revert the change and re-run: `6 passed`.

- [ ] **Step 8: Confirm runtime code is untouched**

These files are untracked in git (the user hasn't baseline-committed them), so `git diff` can't show changes. Compare against the checksums taken in Task 0, Step 3:

Run: `sha256sum -c "$TEMP/protected-files.sha256"`
Expected: every line ends in `OK`.

Commit **only** the new files:

- [ ] **Step 9: Commit**

```bash
git add analyzers/AbuseIPDB/.dockerignore analyzers/AbuseIPDB/tests/
git commit -m "test: add AbuseIPDB tests using the shared harness"
```

---

### Task 6: CI workflow

**Files:**
- Create: `.github/workflows/tests.yml`

- [ ] **Step 1: Write `.github/workflows/tests.yml`**

The action SHAs are pinned the same way as in `build.yml`: `actions/checkout` v7.0.1 (same SHA as `build.yml`) and `actions/setup-python` v7.0.0. Matrix values go through `env:` and are never interpolated into scripts, matching the injection hardening in `build.yml`.

```yaml
name: tests

on:
  pull_request:
  push:
    branches:
      - main
      - develop
  workflow_dispatch:

permissions:
  contents: read

jobs:
  discover:
    name: Discover analyzers with tests
    runs-on: ubuntu-latest
    outputs:
      analyzers: ${{ steps.find.outputs.analyzers }}
    steps:
      - name: Checkout repository
        uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1

      - name: Find analyzers/*/tests
        id: find
        run: |
          analyzers=$(find analyzers -mindepth 2 -maxdepth 2 -type d -name tests \
            | cut -d/ -f2 | sort | jq -R -s -c 'split("\n")[:-1]')
          echo "Analyzers with tests: $analyzers"
          echo "analyzers=$analyzers" >> "$GITHUB_OUTPUT"

  analyzer-tests:
    name: test (${{ matrix.analyzer }})
    needs: discover
    if: needs.discover.outputs.analyzers != '[]'
    runs-on: ubuntu-latest
    strategy:
      fail-fast: false
      matrix:
        analyzer: ${{ fromJson(needs.discover.outputs.analyzers) }}
    steps:
      - name: Checkout repository
        uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1

      - name: Set up Python
        uses: actions/setup-python@5fda3b95a4ea91299a34e894583c3862153e4b97 # v7.0.0
        with:
          python-version: "3.12"

      - name: Install dependencies
        env:
          ANALYZER: ${{ matrix.analyzer }}
        run: |
          python -m pip install --upgrade pip
          pip install -r "analyzers/$ANALYZER/requirements.txt" \
                      -r "analyzers/$ANALYZER/tests/requirements-test.txt"

      - name: Run tests
        env:
          ANALYZER: ${{ matrix.analyzer }}
        run: python -m pytest "analyzers/$ANALYZER/tests" -v

  template-check:
    name: template-check
    runs-on: ubuntu-latest
    steps:
      - name: Checkout repository
        uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1

      - name: Set up Python
        uses: actions/setup-python@5fda3b95a4ea91299a34e894583c3862153e4b97 # v7.0.0
        with:
          python-version: "3.12"

      - name: Install dependencies
        run: |
          python -m pip install --upgrade pip
          pip install -r utils/tests/requirements-test.txt

      - name: Test the scaffolding script and the template it generates
        run: python -m pytest utils/tests -v

  # Single stable check name for branch protection; matrix job names change
  # whenever an analyzer is added.
  tests-passed:
    name: tests-passed
    if: always()
    needs: [discover, analyzer-tests, template-check]
    runs-on: ubuntu-latest
    steps:
      - name: Check results
        env:
          DISCOVER: ${{ needs.discover.result }}
          ANALYZERS: ${{ needs.analyzer-tests.result }}
          TEMPLATE: ${{ needs.template-check.result }}
        run: |
          echo "discover=$DISCOVER analyzer-tests=$ANALYZERS template-check=$TEMPLATE"
          [ "$DISCOVER" = "success" ] || exit 1
          [ "$ANALYZERS" = "success" ] || [ "$ANALYZERS" = "skipped" ] || exit 1
          [ "$TEMPLATE" = "success" ] || exit 1
```

- [ ] **Step 2: Validate the YAML parses**

```bash
.venv/Scripts/python -m pip install -q pyyaml
.venv/Scripts/python -c "import yaml; d = yaml.safe_load(open('.github/workflows/tests.yml')); print(list(d['jobs']))"
```

Expected: `['discover', 'analyzer-tests', 'template-check', 'tests-passed']`

- [ ] **Step 3: Dry-run the discover pipeline locally**

(`jq` exists on GitHub runners; this uses Python in its place.)

```bash
find analyzers -mindepth 2 -maxdepth 2 -type d -name tests | cut -d/ -f2 | sort \
  | .venv/Scripts/python -c "import sys, json; print(json.dumps(sys.stdin.read().split(chr(10))[:-1]))"
```

Expected: `["AbuseIPDB"]`

- [ ] **Step 4: Run exactly what CI runs, locally**

```bash
.venv/Scripts/python -m pytest analyzers/AbuseIPDB/tests -q
.venv/Scripts/python -m pytest utils/tests -q
```

Expected: `6 passed`, then `18 passed`.

- [ ] **Step 5: Commit**

```bash
git add .github/workflows/tests.yml
git commit -m "ci: run analyzer and template tests on PRs and pushes"
```

---

### Task 7: Documentation

**Files:**
- Create: `docs/creating-an-analyzer.md`
- Modify: `README.md` (currently two lines: `# Cortex-Analyzers` / `Cortex Analyzers Repository`)

- [ ] **Step 1: Write `docs/creating-an-analyzer.md`**

````markdown
# Creating an analyzer

New analyzers are generated from `templates/analyzer/`. The generated code is a working example against an invented API, with its own passing tests, so you start from green and change one piece at a time.

## 1. Scaffold

```bash
python utils/new-analyzer.py --name Shodan --datatypes ip,domain
```

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
- One handler method per data type (replace `_lookup_ip`), registered in the `handlers` dict in `run()`. Each returns a dict with `query_type`, `found` and the API data.
- `summary()`: map the response to taxonomies (see below).
- `artifacts()`: extract related observables.

Keep all HTTP inside `_request()`. It already handles timeouts, auth failures, rate limits, 404 → "not found", and other HTTP errors, with messages that end up in IRIS.

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
2. Update `tests/test_shodan.py`: URLs, fixtures, and the exact expected taxonomies and artifacts. Keep the error-path tests (401, 429, 500, timeout, unsupported type, TLP); they test `_request()` and the flavor config.
3. Run:

```bash
python -m venv .venv
.venv/Scripts/python -m pip install -r analyzers/Shodan/requirements.txt -r analyzers/Shodan/tests/requirements-test.txt
.venv/Scripts/python -m pytest analyzers/Shodan/tests -v
```

(On Linux/macOS, use `.venv/bin/python`.)

Assert the **full** taxonomy list, not just one item: `cortexutils` silently replaces a crashing `summary()` with `{}`, and only an exact assertion catches that.

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
````

- [ ] **Step 2: Replace `README.md` content**

````markdown
# Cortex-Analyzers

Cortex Analyzers Repository

## Creating a new analyzer

```bash
python utils/new-analyzer.py --name MyService --datatypes ip,domain
```

See [docs/creating-an-analyzer.md](docs/creating-an-analyzer.md) for the full workflow: filling in the template, taxonomy conventions for Shuffle → IRIS, tests, and CI.
````

- [ ] **Step 3: Commit**

```bash
git add docs/creating-an-analyzer.md README.md
git commit -m "docs: add guide for creating analyzers from the template"
```

---

### Task 8: Final verification

- [ ] **Step 1: Full local run, as CI does it**

```bash
.venv/Scripts/python -m pytest analyzers/AbuseIPDB/tests utils/tests -q
```

Expected: `24 passed`.

- [ ] **Step 2: Check the success criteria from the spec**

```bash
# build.yml / publish-catalogs.yml must not see the skeleton
find analyzers -maxdepth 2 -name '*.json'          # expect only analyzers/AbuseIPDB/AbuseIPDB.json
ls thehive-templates                                # expect only AbuseIPDB_2_0
# AbuseIPDB code, existing workflows and TheHive templates unchanged (checksums from Task 0)
sha256sum -c "$TEMP/protected-files.sha256"          # expect six lines ending in OK
# no leftover demo output
git status --short | grep -E "Demo|CiSmoke"         # expect no output
```

- [ ] **Step 3: Review the branch log**

Run: `git log --oneline main..HEAD`
Expected: the spec and plan commit(s) plus the 7 task commits (Tasks 1–7).

Pushing the branch and opening the PR are **not** part of this plan; ask the user first.
