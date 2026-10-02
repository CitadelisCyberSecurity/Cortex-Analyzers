#!/usr/bin/env python3

import ipaddress
import socket
from urllib.parse import urlparse

import requests

from cortexutils.analyzer import Analyzer


class ProxyCheckAnalyzer(Analyzer):
    """
    proxycheck.io v3 docs: https://proxycheck.io/api/
    """

    API_URL = "https://proxycheck.io/v3/{}"

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

    def _lookup(self, ips, key):
        """Query proxycheck.io for one or more IPs in a single request"""
        params = {"tag": 0}
        if key:
            params["key"] = key
        response = requests.get(
            self.API_URL.format(",".join(ips)),
            params=params,
            headers={"User-Agent": "strangebee-thehive/1.0"},
            timeout=30,
        )
        try:
            json_response = response.json()
        except ValueError:
            json_response = {}

        status = json_response.get("status")
        message = json_response.get("message")
        if not (200 <= response.status_code < 300) or status in ("denied", "error"):
            self.error(
                f"Unable to query proxycheck.io API (HTTP {response.status_code}, status {status})\n"
                f"{message or response.text}"
            )

        results = [dict(ip=ip, **json_response[ip]) for ip in ips if isinstance(json_response.get(ip), dict)]
        return status, message, results

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

            key = self.get_param("config.key", None)
            limit = int(self.get_param("config.max_resolved_ips", 5) or 5)
            data = self.get_data()

            ips, resolved = self._hosts_for_observable(data, limit)
            status, message, results = self._lookup(ips, key)

            self.report({
                "query": data,
                "resolved": resolved,
                "status": status,
                "message": message,
                "results": results,
            })
        except Exception as e:
            self.unexpectedError(e)

    def summary(self, raw):
        taxonomies = []
        results = raw.get("results") or []
        if not results:
            return {"taxonomies": taxonomies}

        flagged = {"tor": 0, "compromised": 0, "proxy": 0, "vpn": 0, "scraper": 0, "hosting": 0}
        countries = []
        asns = []
        risk = None
        for r in results:
            detections = r.get("detections") or {}
            for flag in flagged:
                if detections.get(flag):
                    flagged[flag] += 1

            score = detections.get("risk", r.get("risk_score"))
            if isinstance(score, (int, float)) and (risk is None or score > risk):
                risk = score

            location = r.get("location") or {}
            cc = location.get("country_code") or location.get("isocode")
            if cc and cc not in countries:
                countries.append(cc)
            asn = (r.get("network") or {}).get("asn")
            if asn and asn not in asns:
                asns.append(asn)

        # With several resolved IPs, show how many were flagged; for one IP, show True
        def value(count):
            return "True" if len(results) == 1 else f"{count}/{len(results)}"

        levels = {
            "tor": ("malicious", "Tor"),
            "compromised": ("malicious", "Compromised"),
            "proxy": ("suspicious", "Proxy"),
            "vpn": ("suspicious", "VPN"),
            "scraper": ("suspicious", "Scraper"),
            "hosting": ("info", "Hosting"),
        }
        for flag, (level, predicate) in levels.items():
            if flagged[flag]:
                taxonomies.append(self.build_taxonomy(level, "ProxyCheck", predicate, value(flagged[flag])))
        if not any(flagged[f] for f in flagged if f != "hosting"):
            taxonomies.append(self.build_taxonomy("safe", "ProxyCheck", "Anonymizer", "None"))

        if risk is not None:
            if risk >= 76:
                level = "malicious"
            elif risk >= 51:
                level = "suspicious"
            elif risk >= 26:
                level = "info"
            else:
                level = "safe"
            taxonomies.append(self.build_taxonomy(level, "ProxyCheck", "Risk", risk))

        if countries:
            taxonomies.append(self.build_taxonomy("info", "ProxyCheck", "Country", ",".join(countries)))
        if asns:
            taxonomies.append(
                self.build_taxonomy("info", "ProxyCheck", "ASN", ",".join(a if a.upper().startswith("AS") else f"AS{a}" for a in asns))
            )

        return {"taxonomies": taxonomies}

    def artifacts(self, raw):
        artifacts = []
        ips_out = set()
        asns_out = set()

        for r in raw.get("results") or []:
            if raw.get("resolved") and r.get("ip"):
                ips_out.add(r["ip"])
            asn = (r.get("network") or {}).get("asn")
            if asn:
                asns_out.add(asn)

        for ip in sorted(ips_out):
            artifacts.append(self.build_artifact("ip", ip, tags=["ProxyCheck"]))
        for asn in sorted(asns_out):
            artifacts.append(self.build_artifact("autonomous-system", asn, tags=["ProxyCheck"]))

        return artifacts


if __name__ == "__main__":
    ProxyCheckAnalyzer().run()
