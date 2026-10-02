#!/usr/bin/env python3
"""__TPL_NAME__ analyzer for Cortex.

Generated from templates/analyzer. Every spot that needs service-specific
code is marked "TODO:". See docs/creating-an-analyzer.md.

API docs: TODO: link to the service's API documentation.
"""

import sys
import traceback
from urllib.parse import quote, quote_plus

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

    # Data type -> handler method name. Must cover every type in the flavor's
    # dataTypeList (a test checks this). TODO: add one handler per data type.
    HANDLERS = {"ip": "_lookup_ip"}

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

    def _redact(self, text):
        if not self.api_key:
            return text
        # requests shows query-string keys URL-encoded, so redact those forms too.
        for form in (self.api_key, quote(self.api_key, safe=""), quote_plus(self.api_key)):
            text = text.replace(form, "REMOVED")
        return text

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
            self.error(f"{self.NAMESPACE}: could not reach the API ({self._redact(str(e))})")

        if response.status_code == 404:
            return None
        if response.status_code in (401, 403):
            self.error(f"{self.NAMESPACE}: authentication failed, check the API key")
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

    def _lookup_ip(self, ip):
        # TODO: call the service's real endpoint for this data type.
        data = self._request("GET", f"/ip/{ip}")
        return {"query_type": "ip", "found": data is not None, "data": data}

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
