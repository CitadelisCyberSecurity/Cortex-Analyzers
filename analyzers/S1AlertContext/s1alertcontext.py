#!/usr/bin/env python3
"""S1AlertContext analyzer for Cortex.

Takes a SentinelOne Unified Alert Management (UAM) alert ID and returns the
alert's details, assets, indicators, observables, process, Purple AI's
investigation and the source's raw alert, in one shape for every source.

UAM is GraphQL only, so this analyzer POSTs. It is read-only by construction:
it sends one hard-coded query document, the alert ID travels only as a
variable, and a test asserts the request body.

API: POST <console>/web/api/v2.1/unifiedalerts/graphql
"""

import json
import re
import sys
import traceback
from urllib.parse import quote, quote_plus

import requests
from cortexutils.analyzer import Analyzer

ALERT_ID_RE = re.compile(r"[A-Za-z0-9-]{1,64}")
MAX_STRING = 500
MAX_COMMAND_LINE = 1000
MAX_PURPLE_RESULT = 2000
MAX_RAW_DATA = 4000
MAX_INDICATORS = 50
MAX_OBSERVABLES = 100
MAX_ASSETS = 20
MAX_RELATED = 20

LIMITS = {"command_line": MAX_COMMAND_LINE, "result": MAX_PURPLE_RESULT}
OBSERVABLE = "{ type typeName name value }"
_ALERT_FIELDS = f"""id externalId name description severity status confidenceLevel classification analystVerdict
    detectionSource {{ product vendor }}
    attackSurfaces detectedAt firstSeenAt lastSeenAt storylineId selfLink
    assets {{ name category subcategory osVersion lastLoggedInUser agentUuid primary tags {{ key value }} }}
    indicators {{
      eventTime title type severity description
      attacks {{ tactic {{ uid name }} technique {{ uid name }} }}
      observables {OBSERVABLE}
    }}
    observables {OBSERVABLE}
    process {{ cmdLine parentName username userDomain file {{ path sha1 sha256 }} }}
    relatedAlerts {{ id name }}
    rawData"""
QUERY = f"""query S1AlertContext($id: ID!) {{
  alert(id: $id) {{
    {_ALERT_FIELDS}
  }}
  aiInvestigations(alertIds: [$id]) {{ status verdict result timestamp }}
}}"""
# Fallback when Purple AI errors null the whole response (see _lookup_alert).
ALERT_ONLY_QUERY = f"""query S1AlertContextAlertOnly($id: ID!) {{
  alert(id: $id) {{
    {_ALERT_FIELDS}
  }}
}}"""


class S1AlertContextAnalyzer(Analyzer):
    QUERY = QUERY
    ALERT_ONLY_QUERY = ALERT_ONLY_QUERY
    GRAPHQL_PATH = "/web/api/v2.1/unifiedalerts/graphql"
    # Taxonomy namespace. Shuffle and n8n match on it: don't rename it.
    NAMESPACE = "S1AlertContext"
    USER_AGENT = "citadelis-cortex-s1alertcontext/1.0"

    HANDLERS = {"other": "_lookup_alert"}

    def __init__(self):
        # cortexutils echoes the config in error reports and only hides names
        # containing its default phrases, which don't include "token".
        super().__init__(secret_phrases=("key", "password", "secret", "token"))
        self.api_token = self.get_param("config.api_token", None, "Missing API token")
        url = str(self.get_param("config.url", None, "Missing console URL"))
        if not url.lower().startswith("https://"):
            # The token goes in a header: never send it over plain HTTP.
            self.error(f"{self.NAMESPACE}: console URL must start with https://")
        self.endpoint = url.rstrip("/") + self.GRAPHQL_PATH
        self.timeout = self.get_param("config.timeout", 30)
        self.truncated = False
        self.session = requests.Session()
        self.session.headers.update(
            {
                "Accept": "application/json",
                "User-Agent": self.USER_AGENT,
                "Authorization": f"ApiToken {self.api_token}",
            }
        )

    def _redact(self, text):
        if not self.api_token:
            return text
        for form in (self.api_token, quote(self.api_token, safe=""), quote_plus(self.api_token)):
            text = text.replace(form, "REMOVED")
        return text

    def _request(self, variables, query=None):
        """POST the fixed query and return the parsed JSON body.

        This is the analyzer's single HTTP entry point. It only ever sends
        QUERY or ALERT_ONLY_QUERY as is; only the variables change. Any failure ends the job through
        self.error().
        """
        try:
            response = self.session.post(
                self.endpoint, json={"query": query or self.QUERY, "variables": variables}, timeout=self.timeout
            )
        except requests.exceptions.Timeout:
            self.error(f"{self.NAMESPACE}: request timed out after {self.timeout}s")
        except requests.exceptions.RequestException as e:
            self.error(f"{self.NAMESPACE}: could not reach the API ({self._redact(str(e))})")

        if response.status_code in (401, 403):
            self.error(
                f"{self.NAMESPACE}: authentication failed (HTTP {response.status_code}), "
                "check the API token and its scope"
            )
        if response.status_code == 429:
            self.error(f"{self.NAMESPACE}: rate limited by the API, try again later")
        if not response.ok:
            self.error(
                f"{self.NAMESPACE}: API returned HTTP {response.status_code}: "
                f"{self._redact(response.text[:500])}"
            )
        try:
            return response.json()
        except ValueError:
            self.error(f"{self.NAMESPACE}: API returned a response that is not JSON")

    def _cut(self, value, limit):
        if isinstance(value, str) and len(value) > limit:
            self.truncated = True
            return value[:limit]
        return value

    def _cap(self, items, limit):
        if len(items) > limit:
            self.truncated = True
        return items[:limit]

    def _clean(self, record):
        """Drop empty fields and cut long strings (command lines get more room)."""
        return {
            k: self._cut(v, LIMITS.get(k, MAX_STRING))
            for k, v in record.items()
            if v not in (None, "", [])
        }

    def _alert(self, a):
        source = a.get("detectionSource") or {}
        return self._clean(
            {
                "id": a.get("id"),
                "external_id": a.get("externalId"),
                "name": a.get("name"),
                "description": a.get("description"),
                "severity": a.get("severity"),
                "status": a.get("status"),
                "confidence": a.get("confidenceLevel"),
                "classification": a.get("classification"),
                "analyst_verdict": a.get("analystVerdict"),
                "product": source.get("product"),
                "vendor": source.get("vendor"),
                "attack_surfaces": a.get("attackSurfaces"),
                "detected_at": a.get("detectedAt"),
                "first_seen_at": a.get("firstSeenAt"),
                "last_seen_at": a.get("lastSeenAt"),
                "storyline_id": a.get("storylineId"),
                "link": a.get("selfLink"),
            }
        )

    def _asset(self, a):
        tags = [f"{t.get('key')}={t.get('value')}" for t in a.get("tags") or []]
        return self._clean(
            {
                "name": a.get("name"),
                "category": a.get("category"),
                "subcategory": a.get("subcategory"),
                "os": a.get("osVersion"),
                "last_logged_in_user": a.get("lastLoggedInUser"),
                "agent_uuid": a.get("agentUuid"),
                "primary": a.get("primary"),
                "tags": tags,
            }
        )

    def _mitre(self, attack):
        tactic = attack.get("tactic") or {}
        technique = attack.get("technique") or {}
        parts = [
            " ".join(filter(None, (x.get("uid"), x.get("name")))) for x in (tactic, technique)
        ]
        return " / ".join(p for p in parts if p)

    def _indicator(self, i):
        return self._clean(
            {
                "time": i.get("eventTime"),
                "title": i.get("title"),
                "type": i.get("type"),
                "severity": i.get("severity"),
                "description": i.get("description"),
                "mitre": [m for m in map(self._mitre, i.get("attacks") or []) if m],
            }
        )

    def _observable(self, o):
        return self._clean({"type": o.get("type") or o.get("typeName"), "name": o.get("name"), "value": o.get("value")})

    def _process(self, p):
        p = p or {}
        file = p.get("file") or {}
        user = "\\".join(filter(None, (p.get("userDomain"), p.get("username"))))
        return self._clean(
            {
                "command_line": p.get("cmdLine"),
                "parent": p.get("parentName"),
                "user": user,
                "file_path": file.get("path"),
                "sha1": file.get("sha1"),
                "sha256": file.get("sha256"),
            }
        )

    def _report(self, alert, investigations):
        indicators = sorted(alert.get("indicators") or [], key=lambda i: i.get("eventTime") or "")
        indicators = self._cap(indicators, MAX_INDICATORS)

        seen, observables = set(), []
        for raw in (alert.get("observables") or []) + [o for i in indicators for o in i.get("observables") or []]:
            o = self._observable(raw)
            key = (o.get("type"), o.get("value"))
            if key not in seen:
                seen.add(key)
                observables.append(o)

        ai = (investigations or [None])[0] or {}
        raw_data = alert.get("rawData")
        raw_data = "" if raw_data is None else json.dumps(raw_data, separators=(",", ":"), ensure_ascii=False)
        purple = self._clean(
            {
                "status": ai.get("status"),
                "verdict": ai.get("verdict"),
                "result": ai.get("result"),
                "timestamp": ai.get("timestamp"),
            }
        )
        return {
            "query_type": "other",
            "found": True,
            "alert": self._alert(alert),
            "assets": [self._asset(a) for a in self._cap(alert.get("assets") or [], MAX_ASSETS)],
            "indicators": [self._indicator(i) for i in indicators],
            "observables": self._cap(observables, MAX_OBSERVABLES),
            "process": self._process(alert.get("process")),
            "purple_ai": purple,
            "related_alerts": [
                self._clean({"id": r.get("id"), "name": r.get("name")})
                for r in self._cap([r for r in alert.get("relatedAlerts") or [] if r], MAX_RELATED)
            ],
            "raw_data": self._cut(raw_data, MAX_RAW_DATA),
            "truncated": self.truncated,
        }

    def _lookup_alert(self, value):
        alert_id = str(value).strip()
        if not ALERT_ID_RE.fullmatch(alert_id):
            self.error(f"{self.NAMESPACE}: observable must be a UAM alert ID (1-64 letters, digits or dashes)")

        variables = {"id": alert_id}
        body = self._request(variables)
        body = body if isinstance(body, dict) else {}
        errors = [e for e in body.get("errors") or [] if isinstance(e, dict)]

        def first_path(e):
            path = e.get("path")
            return path[0] if isinstance(path, list) and path else None

        data = body.get("data")
        if data is None and errors and all(first_path(e) == "aiInvestigations" for e in errors):
            # alert and aiInvestigations are non-null in the schema, so a Purple AI
            # error (e.g. no license) nulls all of data. Retry without Purple AI.
            body = self._request(variables, self.ALERT_ONLY_QUERY)
            body = body if isinstance(body, dict) else {}
            errors = [e for e in body.get("errors") or [] if isinstance(e, dict)]
            data = body.get("data")
        data = data if isinstance(data, dict) else {}
        alert = data.get("alert")
        if alert is not None:
            return self._report(alert, data.get("aiInvestigations"))

        messages = [str(e.get("message", "")) for e in errors]
        # shortcut: not-found detection matches error text, and the Purple AI null-propagation
        # retry assumes the schema's non-null behaviour; confirm both against a real tenant response
        if any(
            first_path(e) in (None, "alert") and re.search("not found", str(e.get("message", "")), re.IGNORECASE)
            for e in errors
        ):
            return {
                "query_type": "other",
                "found": False,
                "alert": {},
                "assets": [],
                "indicators": [],
                "observables": [],
                "process": {},
                "purple_ai": {},
                "related_alerts": [],
                "raw_data": "",
                "truncated": False,
            }
        detail = self._redact("; ".join(messages))[:MAX_STRING] or "no data in response"
        self.error(f"{self.NAMESPACE}: GraphQL error: {detail}")

    def run(self):
        try:
            handler_name = self.HANDLERS.get(self.data_type)
            if handler_name is None:
                self.notSupported()
            self.report(getattr(self, handler_name)(self.get_data()))
        except Exception as e:
            traceback.print_exc(file=sys.stderr)
            self.unexpectedError(e)

    def report(self, full_report, ensure_ascii=False):
        # cortexutils' report() swallows summary() errors and sends an empty
        # summary, so Shuffle would get no taxonomies. Fail the job instead.
        # summary() runs twice (here and in super()), so keep it pure: no API calls.
        self.summary(full_report)
        super().report(full_report, ensure_ascii)

    def summary(self, raw):
        """Taxonomies are a contract with n8n: never rename a predicate."""
        ns = self.NAMESPACE
        if not raw.get("found"):
            return {"taxonomies": [self.build_taxonomy("safe", ns, "Found", "False")]}

        alert = raw.get("alert") or {}
        taxonomies = [self.build_taxonomy("info", ns, "Found", "True")]
        confidence = alert.get("confidence")
        if confidence:
            level = confidence.lower() if confidence in ("MALICIOUS", "SUSPICIOUS") else "info"
            taxonomies.append(self.build_taxonomy(level, ns, "Confidence", confidence))
        for predicate, key in (
            ("Severity", "severity"),
            ("Product", "product"),
            ("Status", "status"),
            ("Verdict", "analyst_verdict"),
        ):
            if alert.get(key):
                taxonomies.append(self.build_taxonomy("info", ns, predicate, alert[key]))
        ai = raw.get("purple_ai") or {}
        if ai.get("status") == "COMPLETED" and ai.get("verdict"):
            # Purple AI's opinion never sets the alert's level.
            taxonomies.append(self.build_taxonomy("info", ns, "PurpleAI", ai["verdict"]))
        taxonomies.append(self.build_taxonomy("info", ns, "Indicators", len(raw.get("indicators") or [])))
        return {"taxonomies": taxonomies}

    def artifacts(self, raw):
        # v1: n8n doesn't read artifacts.
        return []


if __name__ == "__main__":
    S1AlertContextAnalyzer().run()
