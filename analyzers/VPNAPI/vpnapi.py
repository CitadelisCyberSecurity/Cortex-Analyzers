#!/usr/bin/env python3

import ipaddress
import socket
from urllib.parse import quote, quote_plus, urlparse

import requests

from cortexutils.analyzer import Analyzer


class VPNAPIAnalyzer(Analyzer):
    """
    VPNAPI.io docs: https://vpnapi.io/api-documentation
    """

    API_URL = "https://vpnapi.io/api/{}"
    USER_AGENT = "citadelis-cortex-vpnapi/1.0"

    @staticmethod
    def _is_ip(value):
        try:
            ipaddress.ip_address(value)
            return True
        except ValueError:
            return False

    def _resolve(self, hostname, limit):
        """Resolve a hostname to a list of unique IPs (IPv4 first)"""
        try:
            infos = socket.getaddrinfo(hostname, None)
        except socket.gaierror as e:
            self.error(f"Unable to resolve {hostname}: {e}")

        ips = []
        for family, _, _, _, sockaddr in sorted(infos, key=lambda i: i[0] != socket.AF_INET):
            ip = sockaddr[0]
            if ip not in ips:
                ips.append(ip)
        return ips[:limit]

    def _lookup(self, ip, key):
        """Query VPNAPI.io for a single IP"""
        try:
            response = requests.get(
                self.API_URL.format(ip),
                params={"key": key},
                headers={"User-Agent": self.USER_AGENT},
                timeout=30,
            )
        except requests.exceptions.Timeout:
            self.error("Request to VPNAPI.io timed out after 30s")
        except requests.exceptions.RequestException as e:
            # The key is in the query string, which requests includes in its errors
            message = str(e)
            for form in (key, quote(key, safe=""), quote_plus(key)):
                message = message.replace(form, "REMOVED")
            self.error(f"Unable to reach VPNAPI.io API: {message}")
        try:
            json_response = response.json()
        except ValueError:
            json_response = {}

        if not (200 <= response.status_code < 300):
            self.error(
                f"Unable to query VPNAPI.io API (HTTP {response.status_code})\n"
                f"{json_response.get('message') or response.text}"
            )
        if "message" in json_response and "security" not in json_response:
            self.error(f"VPNAPI.io error: {json_response['message']}")

        return json_response

    def _hosts_for_observable(self, data, limit):
        if self.data_type == "ip":
            return [data], False

        if self.data_type == "url":
            host = urlparse(data if "://" in data else f"http://{data}").hostname
            if not host:
                self.error(f"Unable to extract a host from URL {data}")
        else:
            host = data.strip().rstrip(".")

        if self._is_ip(host):
            return [host], False
        return self._resolve(host, limit), True

    def run(self):
        try:
            if self.data_type not in ("ip", "domain", "fqdn", "url"):
                self.notSupported()

            key = self.get_param("config.key", None, "Missing VPNAPI.io API key")
            limit = int(self.get_param("config.max_resolved_ips", 5) or 5)
            data = self.get_data()

            ips, resolved = self._hosts_for_observable(data, limit)
            # Drop responses without security data so they don't read as "safe"
            results = [r for r in (self._lookup(ip, key) for ip in ips) if isinstance(r.get("security"), dict)]

            self.report({"query": data, "resolved": resolved, "results": results})
        except Exception as e:
            self.unexpectedError(e)

    def summary(self, raw):
        taxonomies = []
        results = raw.get("results") or []
        if not results:
            # Every successful run needs at least one taxonomy for Shuffle to match on
            return {"taxonomies": [self.build_taxonomy("info", "VPNAPI", "Found", "False")]}

        flagged = {"tor": 0, "vpn": 0, "proxy": 0, "relay": 0}
        countries = []
        asns = []
        for r in results:
            security = r.get("security") or {}
            for flag in flagged:
                if security.get(flag):
                    flagged[flag] += 1

            cc = (r.get("location") or {}).get("country_code")
            if cc and cc not in countries:
                countries.append(cc)
            asn = (r.get("network") or {}).get("autonomous_system_number")
            if asn and asn not in asns:
                asns.append(asn)

        # With several resolved IPs, show how many were flagged; for one IP, show True
        def value(count):
            return "True" if len(results) == 1 else f"{count}/{len(results)}"

        if flagged["tor"]:
            taxonomies.append(self.build_taxonomy("malicious", "VPNAPI", "Tor", value(flagged["tor"])))
        if flagged["vpn"]:
            taxonomies.append(self.build_taxonomy("suspicious", "VPNAPI", "VPN", value(flagged["vpn"])))
        if flagged["proxy"]:
            taxonomies.append(self.build_taxonomy("suspicious", "VPNAPI", "Proxy", value(flagged["proxy"])))
        if flagged["relay"]:
            taxonomies.append(self.build_taxonomy("suspicious", "VPNAPI", "Relay", value(flagged["relay"])))
        if not any(flagged.values()):
            taxonomies.append(self.build_taxonomy("safe", "VPNAPI", "Anonymizer", "None"))

        if countries:
            taxonomies.append(self.build_taxonomy("info", "VPNAPI", "Country", ",".join(countries)))
        if asns:
            taxonomies.append(
                self.build_taxonomy("info", "VPNAPI", "ASN", ",".join(a if a.upper().startswith("AS") else f"AS{a}" for a in asns))
            )

        return {"taxonomies": taxonomies}

    def artifacts(self, raw):
        artifacts = []
        ips_out = set()
        asns_out = set()

        for r in raw.get("results") or []:
            if raw.get("resolved") and r.get("ip"):
                ips_out.add(r["ip"])
            asn = (r.get("network") or {}).get("autonomous_system_number")
            if asn:
                asns_out.add(asn)

        for ip in sorted(ips_out):
            artifacts.append(self.build_artifact("ip", ip, tags=["VPNAPI"]))
        for asn in sorted(asns_out):
            artifacts.append(self.build_artifact("autonomous-system", asn, tags=["VPNAPI"]))

        return artifacts


if __name__ == "__main__":
    VPNAPIAnalyzer().run()
