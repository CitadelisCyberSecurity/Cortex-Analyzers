#!/usr/bin/env python3
"""Set up a fresh dev Cortex (dev/docker-compose.yml) so analyzers can be tested.

Creates the database, a superadmin, an organization with an org admin, enables
every analyzer found in analyzers/ for that organization, and prints the org
admin's API key. Safe to re-run: steps that are already done are skipped,
except the API key, which is replaced on every run.

Analyzer configuration (API keys etc.) is read from dev/analyzers.local.json if
it exists, e.g. {"ProxyCheck_1_0": {"key": "..."}}. That file is gitignored.

Standard library only, so it runs with any Python 3.
"""

import argparse
import http.cookiejar
import json
import sys
import urllib.error
import urllib.request
from pathlib import Path

DEV_DIR = Path(__file__).resolve().parent
ANALYZERS_DIR = DEV_DIR.parent / "analyzers"
LOCAL_CONFIG = DEV_DIR / "analyzers.local.json"

SUPERADMIN = ("admin", "admin")
ORG = "citadelis"
ORG_ADMIN = ("citadelis-admin", "citadelis-admin")


class Cortex:
    def __init__(self, url):
        self.url = url.rstrip("/")
        self.cookies = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.cookies))
        self.api_key = None

    def call(self, method, path, body=None, ok=(200, 201, 204)):
        """Return (status, parsed body). Raises SystemExit on unexpected status."""
        data = json.dumps(body).encode() if body is not None else None
        request = urllib.request.Request(f"{self.url}{path}", data=data, method=method)
        if data is not None:
            request.add_header("Content-Type", "application/json")
        if self.api_key:
            request.add_header("Authorization", f"Bearer {self.api_key}")
        else:
            # Cookie sessions need the XSRF token Cortex hands out at login.
            for cookie in self.cookies:
                if cookie.name == "CORTEX-XSRF-TOKEN":
                    request.add_header("X-CORTEX-XSRF-TOKEN", cookie.value)
        try:
            with self.opener.open(request, timeout=120) as response:
                status, raw = response.status, response.read()
        except urllib.error.HTTPError as e:
            status, raw = e.code, e.read()
        try:
            parsed = json.loads(raw) if raw else None
        except ValueError:
            parsed = raw.decode(errors="replace")
        if status not in ok:
            sys.exit(f"{method} {path} failed: HTTP {status}: {parsed}")
        return status, parsed


def analyzer_definitions():
    """Yield (definition id, flavor) for every flavor JSON under analyzers/."""
    for flavor_path in sorted(ANALYZERS_DIR.glob("*/*.json")):
        flavor = json.loads(flavor_path.read_text(encoding="utf-8"))
        if "name" in flavor and "version" in flavor:
            yield f"{flavor['name']}_{flavor['version']}".replace(".", "_"), flavor


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--url", default="http://127.0.0.1:9001")
    args = parser.parse_args()

    cortex = Cortex(args.url)
    local_config = json.loads(LOCAL_CONFIG.read_text(encoding="utf-8")) if LOCAL_CONFIG.exists() else {}

    print("Creating/upgrading the database")
    cortex.call("POST", "/api/maintenance/migrate", {})

    # Creating a user without logging in only works while there are no users.
    status, _ = cortex.call(
        "POST",
        "/api/user",
        {"login": SUPERADMIN[0], "name": "Admin", "roles": ["superadmin"], "password": SUPERADMIN[1], "organization": "cortex"},
        ok=(201, 400, 401, 403),
    )
    print("Created superadmin" if status == 201 else "Superadmin already exists")

    cortex.call("POST", "/api/login", {"user": SUPERADMIN[0], "password": SUPERADMIN[1]})
    # The XSRF cookie is only set on a GET; POSTs are rejected without it.
    cortex.call("GET", "/api/user/current")

    status, _ = cortex.call("GET", f"/api/organization/{ORG}", ok=(200, 404))
    if status == 404:
        cortex.call("POST", "/api/organization", {"name": ORG, "description": "Dev organization", "status": "Active"})
        print(f"Created organization {ORG}")

    status, _ = cortex.call("GET", f"/api/user/{ORG_ADMIN[0]}", ok=(200, 404))
    if status == 404:
        cortex.call(
            "POST",
            "/api/user",
            {"login": ORG_ADMIN[0], "name": "Citadelis Admin", "roles": ["read", "analyze", "orgadmin"], "organization": ORG},
        )
        cortex.call("POST", f"/api/user/{ORG_ADMIN[0]}/password/set", {"password": ORG_ADMIN[1]})
        print(f"Created org admin {ORG_ADMIN[0]}")

    # Cortex 4 can't show an existing key, so issue a new one (the old one stops working).
    _, key = cortex.call("POST", f"/api/user/{ORG_ADMIN[0]}/key/renew")

    # Analyzers are enabled per organization, by that organization's admin.
    # Use a fresh client: Cortex prefers the superadmin session cookie over the key.
    cortex = Cortex(args.url)
    cortex.api_key = key
    _, enabled = cortex.call("GET", "/api/organization/analyzer?range=all")
    enabled_ids = {a["analyzerDefinitionId"]: a["id"] for a in enabled}
    for definition_id, flavor in analyzer_definitions():
        configuration = {
            item["name"]: item["defaultValue"]
            for item in flavor.get("configurationItems", [])
            if "defaultValue" in item
        }
        # Org-level TLP/PAP settings override the flavor's, and the API stores
        # them as null (check off) unless sent. Copy them like the UI does.
        configuration.update(
            {k: v for k, v in flavor.get("config", {}).items() if k in ("check_tlp", "max_tlp", "check_pap", "max_pap")}
        )
        configuration.update(local_config.get(definition_id, {}))
        if definition_id in enabled_ids:
            cortex.call(
                "PATCH",
                f"/api/analyzer/{enabled_ids[definition_id]}",
                {"configuration": configuration},
            )
            print(f"Updated analyzer {definition_id}")
        else:
            cortex.call(
                "POST",
                f"/api/organization/analyzer/{definition_id}",
                {"name": definition_id, "configuration": configuration},
            )
            print(f"Enabled analyzer {definition_id}")

    print()
    print(f"Cortex UI:      {args.url}")
    print(f"Superadmin:     {SUPERADMIN[0]} / {SUPERADMIN[1]}")
    print(f"Org admin:      {ORG_ADMIN[0]} / {ORG_ADMIN[1]}  (organization {ORG})")
    print(f"Org admin key:  {key}")


if __name__ == "__main__":
    main()
