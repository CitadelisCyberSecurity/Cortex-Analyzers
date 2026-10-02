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
