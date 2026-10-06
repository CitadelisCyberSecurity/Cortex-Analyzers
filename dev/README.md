# Local Cortex for testing analyzers

A throwaway Cortex 4.1 + Elasticsearch 8 stack that runs the analyzers in this
repo from locally built Docker images. Use it after the unit tests pass, to
check an analyzer the way Cortex really runs it.

**Not for production:** Elasticsearch has security off, Cortex is given the
host's Docker socket, and the bootstrap creates users with fixed passwords.
Cortex listens on 127.0.0.1 only.

## Requirements

- Docker Desktop (or Docker Engine) with Compose v2, about 2 GB of free memory
- Python 3 (standard library only)

## Start

From the repository root:

```sh
docker compose -f dev/docker-compose.yml --profile analyzers build   # build the analyzer images
docker compose -f dev/docker-compose.yml up -d
python dev/bootstrap.py
```

Cortex takes about a minute to start. `bootstrap.py` sets up the database, creates
the users below, enables every analyzer in `analyzers/` for the `citadelis`
organization, and prints an API key for the org admin. You can re-run it at any
time; it updates the analyzers' configuration but also replaces the API key.

| Login | Password | Use |
|---|---|---|
| `admin` | `admin` | superadmin: organizations and users |
| `citadelis-admin` | `citadelis-admin` | org admin: analyzers, running jobs |

UI: <http://127.0.0.1:9001>

## Run a job

```sh
python dev/run_job.py ProxyCheck_1_0 ip 1.1.1.1            # summary + artifacts
python dev/run_job.py ProxyCheck_1_0 domain example.com --full
python dev/run_job.py ProxyCheck_1_0 ip 1.1.1.1 --tlp 3     # should fail: max TLP is 2
```

Or log in as `citadelis-admin` and use **New Analysis** in the UI.

## Analyzer API keys

Put them in `dev/analyzers.local.json` (gitignored), keyed by analyzer
definition id, then re-run `bootstrap.py`:

```json
{
    "ProxyCheck_1_0": {"key": "your-proxycheck-key"}
}
```

ProxyCheck works without a key (100 queries a day).

## After changing an analyzer

- **Code change:** rebuild the image with
  `docker compose -f dev/docker-compose.yml --profile analyzers build`.
  `run_job.py` always skips Cortex's job cache, so its next job runs the new
  code. Jobs started from the UI reuse a result for the same observable for
  10 minutes (the analyzer's `jobCache` setting).
- **Flavor JSON change** (new config item, data type...): in the UI, go to
  Organization → Analyzers → **Refresh analyzers**, then re-run `bootstrap.py`.
- **New analyzer:** add a build-only service for it in `docker-compose.yml`,
  like `proxycheck`. Its `image` must match `dockerImage` in the flavor.
  Then rebuild, refresh, and re-run `bootstrap.py`.

## How it works

- Cortex reads the flavor JSON files straight from `analyzers/` (mounted
  read-only) and runs each job as a container from that flavor's `dockerImage`.
- It starts those containers through the host's Docker daemon
  (`/var/run/docker.sock`). Job input and output are shared through
  `/tmp/cortex-jobs`, which has the same path in Cortex and on the Docker host.
  With Docker Desktop that path is inside the Docker VM, not on Windows/macOS.
- Image pulls are off (`dev/cortex/application.conf`), because the analyzer
  images only exist locally.

## Stop and reset

```sh
docker compose -f dev/docker-compose.yml down       # stop, keep data
docker compose -f dev/docker-compose.yml down -v    # stop and delete all Cortex data
```
