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
RESERVED_MODULES = {"requests", "cortexutils", "responses", "pytest", "conftest"}

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
    if name.lower() in sys.stdlib_module_names or name.lower() in RESERVED_MODULES:
        raise ScaffoldError(
            f"Invalid name {name!r}: {name.lower()}.py would shadow the Python module "
            f"{name.lower()!r}; pick another name"
        )
    return name


def parse_datatypes(value):
    return validate_datatypes([d.strip() for d in value.split(",") if d.strip()])


def validate_datatypes(datatypes):
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
        "__TPL_AUTHOR__": json.dumps(author)[1:-1],
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
        data = src.read_bytes()
        try:
            data = _replace(data.decode("utf-8"), tokens).encode("utf-8")
        except UnicodeDecodeError:
            pass  # binary file (logo, screenshot): copy unchanged
        dst.write_bytes(data)
        created.append(dst)
    return created


def scaffold(name, datatypes, author, version, repo_root, with_thehive_templates=False):
    """Create the analyzer and return the list of files written."""
    validate_name(name)
    validate_version(version)
    validate_datatypes(datatypes)
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
        f"  5. Add a build-only service to dev/docker-compose.yml with "
        f"image: ghcr.io/citadeliscybersecurity/{args.name.lower()}:devel\n"
        "  6. bash utils/validate-analyzers.sh\n"
        "See docs/creating-an-analyzer.md for details."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
