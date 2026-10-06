# Cortex-Analyzers (Citadelis)

Custom Cortex analyzers. Each lives in `analyzers/<Name>/` with a flavor JSON, a Python program and tests. `build.yml` builds each one (generating a Dockerfile if the folder has none) and publishes the images to GHCR on push to `main`.

## Rules CI enforces

- `dockerImage` in every flavor JSON must start with `ghcr.io/citadeliscybersecurity/` (use `<name lowercased>:devel`). Never `customimages/...`.
- Required flavor fields, name rules and the registry rule live in `utils/validate-analyzers.sh`. It runs on every PR (`definitions-check`) and in `build.yml`. Change the rules there, not in the workflows.
- `tests-passed` in `.github/workflows/tests.yml` is the single status check for branch protection; add new PR jobs to its `needs`.

## New analyzers

- Always scaffold with `python utils/new-analyzer.py --name <Name> --datatypes ...`; don't hand-write one. Full guide: `docs/creating-an-analyzer.md`.
- ProxyCheck is the reference implementation. Match its conventions: all HTTP in `_request()`, User-Agent header, API key redacted from every error message, at least one taxonomy on success, a `tests/` suite with mocked HTTP and fixtures, `.dockerignore`.
- Taxonomy predicates are a contract with Shuffle; renaming one is a breaking change.
- To test in a real Cortex, add a build-only service to `dev/docker-compose.yml` whose `image:` equals the flavor's `dockerImage`. See `dev/README.md`.

## Before opening a PR

```bash
bash utils/validate-analyzers.sh                # needs jq
python -m pytest analyzers/<Name>/tests -v
python -m pytest utils/tests -v                 # if you touched templates/ or utils/
```

## Windows gotchas

- `core.autocrlf=true` would give shell scripts CRLF endings that bash rejects; `.gitattributes` pins `*.sh` to LF. Keep it that way.
- `jq` isn't installed by default. Run the validation in CI or a container, e.g. `docker run --rm -v "$PWD:/repo" -w /repo alpine sh -c 'apk add -q bash jq && bash utils/validate-analyzers.sh'`.
