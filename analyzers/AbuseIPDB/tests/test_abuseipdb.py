"""Tests for the AbuseIPDB analyzer.

Fixtures follow the AbuseIPDB APIv2 response shapes
(https://docs.abuseipdb.com/). All HTTP is mocked; see conftest.py.
"""

from responses import matchers

CHECK_URL = "https://api.abuseipdb.com/api/v2/check"
BLOCK_URL = "https://api.abuseipdb.com/api/v2/check-block"
NS = "AbuseIPDB"


def test_single_ip_check(run_analyzer, mocked_api, load_fixture):
    mocked_api.get(
        CHECK_URL,
        json=load_fixture("check_tor_exit.json"),
        match=[
            matchers.query_param_matcher(
                {"maxAgeInDays": "30", "verbose": "True", "ipAddress": "185.220.101.1"}
            ),
            matchers.header_matcher({"Key": "test-key"}),
        ],
    )

    output = run_analyzer("185.220.101.1")

    assert output["success"] is True
    assert output["summary"]["taxonomies"] == [
        {"level": "info", "namespace": NS, "predicate": "Tor", "value": "True"},
        {"level": "info", "namespace": NS, "predicate": "Usage", "value": "Data Center/Web Hosting/Transit"},
        {"level": "malicious", "namespace": NS, "predicate": "Score", "value": 100},
        {"level": "malicious", "namespace": NS, "predicate": "Reports", "value": 2},
    ]
    assert output["artifacts"] == [
        {"dataType": "domain", "data": "example-hosting.de", "tags": [NS]},
        {"dataType": "fqdn", "data": "tor-exit-1.example-hosting.de", "tags": [NS]},
    ]
    report = output["full"]
    assert report["query_type"] == "check"
    assert report["values"][0]["categories_strings"] == ["Brute Force", "SSH", "Port Scan"]


def test_days_config_is_sent(run_analyzer, mocked_api, load_fixture):
    mocked_api.get(
        CHECK_URL,
        json=load_fixture("check_tor_exit.json"),
        match=[matchers.query_param_matcher(
            {"maxAgeInDays": "90", "verbose": "True", "ipAddress": "185.220.101.1"}
        )],
    )

    output = run_analyzer("185.220.101.1", config={"days": 90})

    assert output["success"] is True


def test_whitelisted_ip_reports_are_info(run_analyzer, mocked_api, load_fixture):
    mocked_api.get(CHECK_URL, json=load_fixture("check_whitelisted.json"))

    output = run_analyzer("8.8.8.8")

    assert output["success"] is True
    assert output["summary"]["taxonomies"] == [
        {"level": "info", "namespace": NS, "predicate": "Whitelisted", "value": "True"},
        {"level": "safe", "namespace": NS, "predicate": "Score", "value": 0},
        {"level": "info", "namespace": NS, "predicate": "Reports", "value": 3},
    ]


def test_cidr_block_check(run_analyzer, mocked_api, load_fixture):
    mocked_api.get(
        BLOCK_URL,
        json=load_fixture("check_block.json"),
        match=[matchers.query_param_matcher({"maxAgeInDays": "30", "network": "192.0.2.0/24"})],
    )

    output = run_analyzer("192.0.2.0/24")

    assert output["success"] is True
    assert output["summary"]["taxonomies"] == [
        {"level": "malicious", "namespace": NS, "predicate": "Max Score", "value": 80},
        {"level": "suspicious", "namespace": NS, "predicate": "Reported IPs", "value": 2},
        {"level": "info", "namespace": NS, "predicate": "Total Reports", "value": 6},
    ]
    assert output["artifacts"] == [
        {"dataType": "ip", "data": "192.0.2.10", "tags": [NS]},
        {"dataType": "ip", "data": "192.0.2.20", "tags": [NS]},
    ]
    assert output["full"]["query_type"] == "check-block"


def test_api_error(run_analyzer, mocked_api):
    mocked_api.get(CHECK_URL, status=401, json={"errors": [{"detail": "Authentication failed."}]})

    output = run_analyzer("185.220.101.1")

    assert output["success"] is False
    assert output["errorMessage"].startswith("Unable to query AbuseIPDB API")
    assert "Authentication failed." in output["errorMessage"]
    assert output["input"]["config"]["key"] == "REMOVED"


def test_tlp_above_max_is_rejected(run_analyzer, mocked_api):
    output = run_analyzer("185.220.101.1", tlp=3)

    assert output["success"] is False
    assert "TLP" in output["errorMessage"]
    assert len(mocked_api.calls) == 0
