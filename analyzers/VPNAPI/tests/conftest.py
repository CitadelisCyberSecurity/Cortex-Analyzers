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
    # Cortex runs "python <Name>/<slug>.py", which puts the analyzer folder first
    # on sys.path. Do the same so a slug like shodan.py shadows "import shodan"
    # here exactly as it would in production.
    sys.path.insert(0, str(ANALYZER_DIR))
    try:
        spec.loader.exec_module(module)
    finally:
        sys.path.remove(str(ANALYZER_DIR))
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
def flavor():
    return FLAVOR


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
        # cortexutils sets these from config.proxy; monkeypatch restores them afterwards.
        monkeypatch.delenv("http_proxy", raising=False)
        monkeypatch.delenv("https_proxy", raising=False)
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
