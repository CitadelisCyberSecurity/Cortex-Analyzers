#!/usr/bin/env python3
"""S1ThreatContext analyzer for Cortex.

Takes a SentinelOne threat ID and returns the threat's details plus what its
storyline did on the endpoint (processes, network, DNS, files, registry).
Read-only: GET requests only.

API docs: <console>/api-doc (Management API v2.1)
  GET /web/api/v2.1/threats?ids=<id>
  GET /web/api/v2.1/threats/<id>/explore/events
"""

import re
import sys
import traceback
from urllib.parse import quote, quote_plus

import requests
from cortexutils.analyzer import Analyzer

THREAT_ID_RE = re.compile(r"[0-9]+")
MAX_STRING = 500
MAX_COMMAND_LINE = 1000
PAGE_LIMIT = 1000  # API maximum for "limit"
EVENT_TYPES = "process,file,ip,dns,registry"
FILE_ACTIONS = (("creat", "create"), ("modif", "modify"), ("delet", "delete"), ("renam", "rename"))
LIST_KEYS = ("processes", "network", "dns", "files", "registry")


class S1ThreatContextAnalyzer(Analyzer):
    API_PATH = "/web/api/v2.1"
    # Taxonomy namespace. Shuffle and n8n match on it: don't rename it.
    NAMESPACE = "S1ThreatContext"
    USER_AGENT = "citadelis-cortex-s1threatcontext/1.0"

    HANDLERS = {"other": "_lookup_threat"}

    def __init__(self):
        # cortexutils echoes the config in error reports and only hides names
        # containing its default phrases, which don't include "token".
        super().__init__(secret_phrases=("key", "password", "secret", "token"))
        self.api_token = self.get_param("config.api_token", None, "Missing API token")
        url = str(self.get_param("config.url", None, "Missing console URL"))
        if not url.lower().startswith("https://"):
            # The token goes in a header: never send it over plain HTTP.
            self.error(f"{self.NAMESPACE}: console URL must start with https://")
        self.base_url = url.rstrip("/") + self.API_PATH
        self.max_events = max(0, int(self.get_param("config.max_events", 50) or 0))
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

    def _request(self, path, params=None):
        """GET one API path and return the parsed JSON body.

        Lookups only: this is the analyzer's single HTTP entry point and it
        only ever sends GET. Returns None on 404/410 (not found, or endpoint
        retired). Any other failure ends the job through self.error().
        """
        try:
            response = self.session.get(f"{self.base_url}{path}", params=params, timeout=self.timeout)
        except requests.exceptions.Timeout:
            self.error(f"{self.NAMESPACE}: request timed out after {self.timeout}s")
        except requests.exceptions.RequestException as e:
            self.error(f"{self.NAMESPACE}: could not reach the API ({self._redact(str(e))})")

        if response.status_code in (404, 410):
            return None
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

    def _clean(self, record):
        """Drop empty fields and cut long strings (command lines get more room)."""
        return {
            k: self._cut(v, MAX_COMMAND_LINE if k == "command_line" else MAX_STRING)
            for k, v in record.items()
            if v not in (None, "")
        }

    def _threat(self, item):
        info = item.get("threatInfo") or {}
        realtime = item.get("agentRealtimeInfo") or {}
        detection = item.get("agentDetectionInfo") or {}
        return self._clean(
            {
                "id": info.get("threatId") or item.get("id"),
                "name": info.get("threatName"),
                "classification": info.get("classification"),
                "confidence": info.get("confidenceLevel"),
                "analyst_verdict": info.get("analystVerdict"),
                "mitigation_status": info.get("mitigationStatus"),
                "incident_status": info.get("incidentStatus"),
                "storyline": info.get("storyline"),
                "file_path": info.get("filePath"),
                "sha1": info.get("sha1"),
                "originator_process": info.get("originatorProcess"),
                "command_line": info.get("maliciousProcessArguments"),
                "process_user": info.get("processUser"),
                "endpoint": realtime.get("agentComputerName"),
                "os": realtime.get("agentOsName") or detection.get("agentOsName"),
                "site": realtime.get("siteName") or detection.get("siteName"),
            }
        )

    def _event(self, e):
        """Map one explore/events item to (list name, record), or None to skip it."""
        kind = e.get("objectType")
        base = {"time": e.get("createdAt"), "process": e.get("processName")}
        if kind == "process":
            return "processes", self._clean(
                {
                    "time": e.get("createdAt"),
                    "name": e.get("processName"),
                    "pid": e.get("pid"),
                    "parent": e.get("parentProcessName"),
                    "user": e.get("processUserName"),
                    "command_line": e.get("processCmd"),
                    "sha1": e.get("processImageSha1Hash") or e.get("sha1"),
                }
            )
        if kind == "ip":
            inbound = (e.get("direction") or "").lower().startswith("in")
            return "network", self._clean(
                {
                    **base,
                    "direction": e.get("direction"),
                    "remote_ip": e.get("srcIp") if inbound else e.get("dstIp"),
                    "remote_port": e.get("srcPort") if inbound else e.get("dstPort"),
                }
            )
        if kind == "dns":
            return "dns", self._clean({**base, "query": e.get("dnsRequest"), "response": e.get("dnsResponse")})
        if kind == "file":
            event_type = (e.get("eventType") or "").lower()
            action = next((a for key, a in FILE_ACTIONS if key in event_type), event_type)
            return "files", self._clean(
                {**base, "action": action, "path": e.get("fileFullName"), "sha1": e.get("fileSha1")}
            )
        if kind == "registry":
            # This endpoint returns no registry value data, so "value" is left out.
            return "registry", self._clean({**base, "action": e.get("eventType"), "key": e.get("registryPath")})
        return None

    def _events(self, threat_id):
        """Page through the storyline events, stopping at max_events."""
        events = []
        cursor = None
        while len(events) < self.max_events:
            params = {
                "eventTypes": EVENT_TYPES,
                "sortBy": "createdAt",
                "sortOrder": "asc",
                "skipCount": "true",
                "limit": min(PAGE_LIMIT, self.max_events - len(events)),
            }
            if cursor:
                params["cursor"] = cursor
            body = self._request(f"/threats/{threat_id}/explore/events", params)
            page = (body or {}).get("data") or []
            events.extend(page)
            cursor = ((body or {}).get("pagination") or {}).get("nextCursor")
            if not cursor or not page:
                break
        if len(events) > self.max_events or (len(events) == self.max_events and cursor):
            self.truncated = True
        return events[: self.max_events]

    def _lookup_threat(self, value):
        threat_id = str(value).strip()
        if not THREAT_ID_RE.fullmatch(threat_id):
            self.error(f"{self.NAMESPACE}: observable must be a numeric SentinelOne threat ID")

        report = {"query_type": "other", "found": False, "threat": {}}
        report.update({key: [] for key in LIST_KEYS})

        data = (self._request("/threats", {"ids": threat_id}) or {}).get("data") or []
        if data:
            report["found"] = True
            report["threat"] = self._threat(data[0])
            for event in self._events(threat_id):
                mapped = self._event(event)
                if mapped:
                    report[mapped[0]].append(mapped[1])
            for key in LIST_KEYS:
                report[key].sort(key=lambda r: r.get("time") or "")
        report["truncated"] = self.truncated
        return report

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

        threat = raw.get("threat") or {}
        taxonomies = [self.build_taxonomy("info", ns, "Found", "True")]
        confidence = threat.get("confidence")
        if confidence:
            level = confidence if confidence in ("malicious", "suspicious") else "info"
            taxonomies.append(self.build_taxonomy(level, ns, "Confidence", confidence))
        if threat.get("analyst_verdict"):
            taxonomies.append(self.build_taxonomy("info", ns, "Verdict", threat["analyst_verdict"]))
        if threat.get("mitigation_status"):
            taxonomies.append(self.build_taxonomy("info", ns, "Mitigation", threat["mitigation_status"]))
        events = sum(len(raw.get(key) or []) for key in LIST_KEYS)
        taxonomies.append(self.build_taxonomy("info", ns, "Events", events))
        return {"taxonomies": taxonomies}

    def artifacts(self, raw):
        # v1: n8n doesn't read artifacts.
        return []


if __name__ == "__main__":
    S1ThreatContextAnalyzer().run()
