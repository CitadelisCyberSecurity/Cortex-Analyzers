"""Tests for the ProxyCheck analyzer.

They run the analyzer exactly as Cortex does (see conftest.py) with all HTTP
and DNS mocked, so no network access or API key is needed. The fixtures follow
the proxycheck.io v3 response format (https://proxycheck.io/api/).
"""

import socket
from urllib.parse import parse_qs, urlparse

import pytest
import requests

NS = "ProxyCheck"
VPN_IP = "203.0.113.10"
CLEAN_IP = "198.51.100.20"


def api_url(analyzer_class, *ips):
    return analyzer_class.API_URL.format(",".join(ips))


def query_params(call):
    return parse_qs(urlparse(call.request.url).query)


def tax(level, predicate, value):
    return {"level": level, "namespace": NS, "predicate": predicate, "value": value}


def only(fixture, ip):
    """Keep a single IP's entry from a multi-IP fixture."""
    return {"status": fixture["status"], ip: fixture[ip]}


@pytest.fixture
def fake_dns(monkeypatch):
    """Replace socket.getaddrinfo with a fixed hostname -> addresses table."""
    lookups = []

    def install(table):
        def getaddrinfo(host, port, *args, **kwargs):
            lookups.append(host)
            if host not in table:
                raise socket.gaierror(socket.EAI_NONAME, "Name or service not known")
            infos = []
            for ip in table[host]:
                if ":" in ip:
                    infos.append((socket.AF_INET6, socket.SOCK_STREAM, 6, "", (ip, 0, 0, 0)))
                else:
                    # getaddrinfo returns one entry per socket type: duplicates are normal.
                    infos.append((socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, 0)))
                    infos.append((socket.AF_INET, socket.SOCK_DGRAM, 17, "", (ip, 0)))
            return infos

        monkeypatch.setattr(socket, "getaddrinfo", getaddrinfo)
        return lookups

    return install


# --- IP observables ---------------------------------------------------------


def test_vpn_ip_reports_taxonomies_and_asn(run_analyzer, mocked_api, analyzer_class, load_fixture):
    mocked_api.get(api_url(analyzer_class, VPN_IP), json=load_fixture("vpn_ip.json"))

    output = run_analyzer(VPN_IP)

    assert output["success"] is True
    assert output["summary"]["taxonomies"] == [
        tax("suspicious", "VPN", "True"),
        tax("info", "Hosting", "True"),
        tax("suspicious", "Risk", 66),
        tax("info", "Country", "NL"),
        tax("info", "ASN", "AS60068"),
    ]
    # The queried IP is the observable itself, so only the ASN is extracted.
    assert output["artifacts"] == [
        {"dataType": "autonomous-system", "data": "AS60068", "tags": [NS]},
    ]
    full = output["full"]
    assert full["query"] == VPN_IP
    assert full["resolved"] is False
    assert full["status"] == "ok"
    assert [r["ip"] for r in full["results"]] == [VPN_IP]
    assert full["results"][0]["operator"]["name"] == "ExampleVPN"


def test_request_sends_key_and_disables_tagging(run_analyzer, mocked_api, analyzer_class, load_fixture):
    mocked_api.get(api_url(analyzer_class, VPN_IP), json=load_fixture("vpn_ip.json"))

    run_analyzer(VPN_IP)

    assert query_params(mocked_api.calls[0]) == {"key": ["test-key"], "tag": ["0"]}


def test_key_is_optional(run_analyzer, mocked_api, analyzer_class, load_fixture):
    mocked_api.get(api_url(analyzer_class, VPN_IP), json=load_fixture("vpn_ip.json"))

    output = run_analyzer(VPN_IP, config={"key": None})

    assert output["success"] is True
    assert "key" not in query_params(mocked_api.calls[0])


def test_clean_ip_is_safe(run_analyzer, mocked_api, analyzer_class, load_fixture):
    mocked_api.get(api_url(analyzer_class, CLEAN_IP), json=only(load_fixture("resolved_ips.json"), CLEAN_IP))

    output = run_analyzer(CLEAN_IP)

    assert output["success"] is True
    assert output["summary"]["taxonomies"] == [
        tax("safe", "Anonymizer", "None"),
        tax("safe", "Risk", 0),
        tax("info", "Country", "US"),
        tax("info", "ASN", "AS7922"),
    ]


def test_hosting_alone_is_still_safe_anonymizer(run_analyzer, mocked_api, analyzer_class, load_fixture):
    body = only(load_fixture("resolved_ips.json"), CLEAN_IP)
    body[CLEAN_IP]["detections"]["hosting"] = True
    mocked_api.get(api_url(analyzer_class, CLEAN_IP), json=body)

    output = run_analyzer(CLEAN_IP)

    taxonomies = output["summary"]["taxonomies"]
    assert tax("info", "Hosting", "True") in taxonomies
    assert tax("safe", "Anonymizer", "None") in taxonomies


@pytest.mark.parametrize(
    "flag, level, predicate",
    [
        ("tor", "malicious", "Tor"),
        ("compromised", "malicious", "Compromised"),
        ("proxy", "suspicious", "Proxy"),
        ("vpn", "suspicious", "VPN"),
        ("scraper", "suspicious", "Scraper"),
    ],
)
def test_each_detection_maps_to_its_level(run_analyzer, mocked_api, analyzer_class, load_fixture, flag, level, predicate):
    body = only(load_fixture("resolved_ips.json"), CLEAN_IP)
    body[CLEAN_IP]["detections"][flag] = True
    mocked_api.get(api_url(analyzer_class, CLEAN_IP), json=body)

    output = run_analyzer(CLEAN_IP)

    taxonomies = output["summary"]["taxonomies"]
    assert taxonomies[0] == tax(level, predicate, "True")
    assert tax("safe", "Anonymizer", "None") not in taxonomies


@pytest.mark.parametrize(
    "risk, level",
    [(0, "safe"), (25, "safe"), (26, "info"), (50, "info"), (51, "suspicious"), (75, "suspicious"), (76, "malicious"), (100, "malicious")],
)
def test_risk_thresholds(run_analyzer, mocked_api, analyzer_class, load_fixture, risk, level):
    body = only(load_fixture("resolved_ips.json"), CLEAN_IP)
    body[CLEAN_IP]["detections"]["risk"] = risk
    mocked_api.get(api_url(analyzer_class, CLEAN_IP), json=body)

    output = run_analyzer(CLEAN_IP)

    assert tax(level, "Risk", risk) in output["summary"]["taxonomies"]


def test_ip_missing_from_response_still_gives_a_taxonomy(run_analyzer, mocked_api, analyzer_class):
    mocked_api.get(api_url(analyzer_class, VPN_IP), json={"status": "ok"})

    output = run_analyzer(VPN_IP)

    assert output["success"] is True
    assert output["full"]["results"] == []
    # No data is not evidence of safety, so this is context rather than a verdict.
    assert output["summary"]["taxonomies"] == [tax("info", "Found", "False")]
    assert output["artifacts"] == []


def test_user_agent_identifies_citadelis(run_analyzer, mocked_api, analyzer_class, load_fixture, flavor):
    mocked_api.get(api_url(analyzer_class, VPN_IP), json=load_fixture("vpn_ip.json"))

    run_analyzer(VPN_IP)

    assert mocked_api.calls[0].request.headers["User-Agent"] == f"citadelis-cortex-proxycheck/{flavor['version']}"


def test_warning_status_still_reports(run_analyzer, mocked_api, analyzer_class, load_fixture):
    body = load_fixture("vpn_ip.json")
    body["status"] = "warning"
    body["message"] = "You're nearing your daily query limit."
    mocked_api.get(api_url(analyzer_class, VPN_IP), json=body)

    output = run_analyzer(VPN_IP)

    assert output["success"] is True
    assert output["full"]["status"] == "warning"
    assert output["full"]["message"] == "You're nearing your daily query limit."


# --- Domain, FQDN and URL observables ----------------------------------------


def test_domain_resolves_and_checks_ips_in_one_request(run_analyzer, mocked_api, analyzer_class, load_fixture, fake_dns):
    fake_dns({"example.com": [VPN_IP, CLEAN_IP]})
    mocked_api.get(api_url(analyzer_class, VPN_IP, CLEAN_IP), json=load_fixture("resolved_ips.json"))

    output = run_analyzer("example.com", data_type="domain")

    assert output["success"] is True
    assert len(mocked_api.calls) == 1
    assert output["full"]["resolved"] is True
    assert [r["ip"] for r in output["full"]["results"]] == [VPN_IP, CLEAN_IP]
    assert output["summary"]["taxonomies"] == [
        tax("suspicious", "VPN", "1/2"),
        tax("info", "Hosting", "1/2"),
        tax("suspicious", "Risk", 66),
        tax("info", "Country", "NL,US"),
        tax("info", "ASN", "AS60068,AS7922"),
    ]
    # Resolved IPs are new observables, so they are extracted along with the ASNs.
    assert output["artifacts"] == [
        {"dataType": "ip", "data": CLEAN_IP, "tags": [NS]},
        {"dataType": "ip", "data": VPN_IP, "tags": [NS]},
        {"dataType": "autonomous-system", "data": "AS60068", "tags": [NS]},
        {"dataType": "autonomous-system", "data": "AS7922", "tags": [NS]},
    ]


def test_resolution_prefers_ipv4_and_respects_limit(run_analyzer, mocked_api, analyzer_class, load_fixture, fake_dns):
    fake_dns({"vpn.example.com": ["2001:db8::1", VPN_IP, CLEAN_IP]})
    mocked_api.get(api_url(analyzer_class, VPN_IP, CLEAN_IP), json=load_fixture("resolved_ips.json"))

    output = run_analyzer("vpn.example.com", data_type="fqdn", config={"max_resolved_ips": 2})

    assert output["success"] is True
    assert [r["ip"] for r in output["full"]["results"]] == [VPN_IP, CLEAN_IP]


def test_fqdn_trailing_dot_is_stripped(run_analyzer, mocked_api, analyzer_class, load_fixture, fake_dns):
    lookups = fake_dns({"vpn.example.com": [VPN_IP]})
    mocked_api.get(api_url(analyzer_class, VPN_IP), json=load_fixture("vpn_ip.json"))

    output = run_analyzer(" vpn.example.com. ", data_type="fqdn")

    assert output["success"] is True
    assert lookups == ["vpn.example.com"]


def test_url_host_is_resolved(run_analyzer, mocked_api, analyzer_class, load_fixture, fake_dns):
    lookups = fake_dns({"vpn.example.com": [VPN_IP]})
    mocked_api.get(api_url(analyzer_class, VPN_IP), json=load_fixture("vpn_ip.json"))

    output = run_analyzer("https://user@vpn.example.com:8443/login?next=/", data_type="url")

    assert output["success"] is True
    assert lookups == ["vpn.example.com"]
    assert output["full"]["resolved"] is True


def test_url_without_scheme_is_accepted(run_analyzer, mocked_api, analyzer_class, load_fixture, fake_dns):
    lookups = fake_dns({"vpn.example.com": [VPN_IP]})
    mocked_api.get(api_url(analyzer_class, VPN_IP), json=load_fixture("vpn_ip.json"))

    output = run_analyzer("vpn.example.com/path", data_type="url")

    assert output["success"] is True
    assert lookups == ["vpn.example.com"]


def test_url_with_ip_host_skips_dns(run_analyzer, mocked_api, analyzer_class, load_fixture, fake_dns):
    lookups = fake_dns({})
    mocked_api.get(api_url(analyzer_class, VPN_IP), json=load_fixture("vpn_ip.json"))

    output = run_analyzer(f"http://{VPN_IP}/payload.bin", data_type="url")

    assert output["success"] is True
    assert lookups == []
    assert output["full"]["resolved"] is False
    assert {"dataType": "ip", "data": VPN_IP, "tags": [NS]} not in output["artifacts"]


def test_url_without_host_is_an_error(run_analyzer, mocked_api):
    output = run_analyzer("http:///nohost", data_type="url")

    assert output["success"] is False
    assert "Unable to extract a host" in output["errorMessage"]
    assert len(mocked_api.calls) == 0


def test_unresolvable_domain_is_an_error(run_analyzer, mocked_api, fake_dns):
    fake_dns({})

    output = run_analyzer("does-not-exist.example", data_type="domain")

    assert output["success"] is False
    assert "Unable to resolve does-not-exist.example" in output["errorMessage"]
    assert len(mocked_api.calls) == 0


# --- Errors -----------------------------------------------------------------


def test_denied_status_is_an_error(run_analyzer, mocked_api, analyzer_class):
    mocked_api.get(
        api_url(analyzer_class, VPN_IP),
        status=429,
        json={"status": "denied", "message": "Daily query limit exceeded."},
    )

    output = run_analyzer(VPN_IP)

    assert output["success"] is False
    assert "HTTP 429" in output["errorMessage"]
    assert "Daily query limit exceeded." in output["errorMessage"]


def test_error_status_with_http_200_is_an_error(run_analyzer, mocked_api, analyzer_class):
    mocked_api.get(api_url(analyzer_class, VPN_IP), json={"status": "error", "message": "Invalid address."})

    output = run_analyzer(VPN_IP)

    assert output["success"] is False
    assert "Invalid address." in output["errorMessage"]


def test_non_json_server_error_includes_body(run_analyzer, mocked_api, analyzer_class):
    mocked_api.get(api_url(analyzer_class, VPN_IP), status=502, body="Bad Gateway")

    output = run_analyzer(VPN_IP)

    assert output["success"] is False
    assert "HTTP 502" in output["errorMessage"]
    assert "Bad Gateway" in output["errorMessage"]
    assert output["input"]["config"]["key"] == "REMOVED"


def test_timeout_is_reported(run_analyzer, mocked_api, analyzer_class):
    mocked_api.get(api_url(analyzer_class, VPN_IP), body=requests.exceptions.ReadTimeout())

    output = run_analyzer(VPN_IP)

    assert output["success"] is False
    assert "timed out" in output["errorMessage"]


def test_api_key_is_redacted_from_connection_errors(run_analyzer, mocked_api, analyzer_class):
    mocked_api.get(
        api_url(analyzer_class, VPN_IP),
        body=requests.exceptions.ConnectionError(
            f"HTTPSConnectionPool(host='proxycheck.io', port=443): "
            f"Max retries exceeded with url: /v3/{VPN_IP}?tag=0&key=test-key"
        ),
    )

    output = run_analyzer(VPN_IP)

    assert output["success"] is False
    assert "test-key" not in output["errorMessage"]
    assert "REMOVED" in output["errorMessage"]


def test_url_encoded_api_key_is_redacted(run_analyzer, mocked_api, analyzer_class):
    mocked_api.get(
        api_url(analyzer_class, VPN_IP),
        body=requests.exceptions.ConnectionError("Max retries exceeded with url: /v3/x?key=ab%2Bc%2Fd%3D"),
    )

    output = run_analyzer(VPN_IP, config={"key": "ab+c/d="})

    assert output["success"] is False
    for form in ("ab+c/d=", "ab%2Bc%2Fd%3D"):
        assert form not in output["errorMessage"]


def test_unsupported_data_type(run_analyzer, mocked_api):
    output = run_analyzer("user@example.com", data_type="mail")

    assert output["success"] is False
    assert "not supported" in output["errorMessage"]


def test_tlp_above_max_is_rejected_before_any_request(run_analyzer, mocked_api):
    output = run_analyzer(VPN_IP, tlp=3)

    assert output["success"] is False
    assert "TLP" in output["errorMessage"]
    assert len(mocked_api.calls) == 0


def test_flavor_data_types_match_the_analyzer(flavor):
    assert sorted(flavor["dataTypeList"]) == ["domain", "fqdn", "ip", "url"]
