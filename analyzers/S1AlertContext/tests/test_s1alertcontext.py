"""Tests for the S1AlertContext analyzer.

They run the analyzer exactly as Cortex does (see conftest.py) with all HTTP
mocked, so no console or token is needed. Fixtures are synthetic: no real
hostnames, users, IPs or tenants.
"""

import copy
import json

import pytest
import requests

ID = "018e1efe-0000-7000-8000-000000000001"
NS = "S1AlertContext"
GQL_URL = "https://console.example.test/web/api/v2.1/unifiedalerts/graphql"
EMPTY = {
    "alert": {},
    "assets": [],
    "indicators": [],
    "observables": [],
    "process": {},
    "purple_ai": {},
    "related_alerts": [],
    "raw_data": "",
}


def tax(level, predicate, value):
    return {"level": level, "namespace": NS, "predicate": predicate, "value": value}


def test_edr_alert_full_report(run_analyzer, mocked_api, load_fixture):
    mocked_api.post(GQL_URL, json=load_fixture("edr_alert.json"))

    output = run_analyzer(ID)

    assert output["success"] is True
    assert output["summary"]["taxonomies"] == [
        tax("info", "Found", "True"),
        tax("suspicious", "Confidence", "SUSPICIOUS"),
        tax("info", "Severity", "HIGH"),
        tax("info", "Product", "EDR"),
        tax("info", "Status", "NEW"),
        tax("info", "Verdict", "UNDEFINED"),
        tax("info", "PurpleAI", "TRUE_POSITIVE"),
        tax("info", "Indicators", 2),
    ]
    assert output["full"] == {
        "query_type": "other",
        "found": True,
        "alert": {
            "id": ID,
            "external_id": "1234567890123456789",
            "name": "Malicious file invoice.exe",
            "description": "A suspicious executable ran on the endpoint.",
            "severity": "HIGH",
            "status": "NEW",
            "confidence": "SUSPICIOUS",
            "classification": "RANSOMWARE",
            "analyst_verdict": "UNDEFINED",
            "product": "EDR",
            "vendor": "SentinelOne",
            "attack_surfaces": ["ENDPOINT"],
            "detected_at": "2026-11-20T10:00:00.000Z",
            "first_seen_at": "2026-11-20T09:59:00.000Z",
            "last_seen_at": "2026-11-20T10:05:00.000Z",
            "storyline_id": "ABCDEF0123456789",
            "link": f"https://console.example.test/alerts/{ID}",
        },
        "assets": [
            {
                "name": "WS-0001.example.test",
                "category": "Workstation",
                "subcategory": "Laptop",
                "os": "Windows 11 Pro",
                "last_logged_in_user": "EXAMPLE\\user1",
                "agent_uuid": "11111111-2222-3333-4444-555555555555",
                "primary": True,
                "tags": ["env=prod", "owner=finance"],
            },
            {
                "name": "FS-0002.example.test",
                "category": "Server",
                "subcategory": "File Server",
                "primary": False,
            },
        ],
        "indicators": [
            {
                "time": "2026-11-20T10:01:00.000Z",
                "title": "Packed executable",
                "type": "PROCESS",
                "severity": "HIGH",
                "mitre": ["TA0005 Stealth / T1027 Obfuscated Files or Information"],
            },
            {
                "time": "2026-11-20T10:03:00.000Z",
                "title": "Outbound connection",
                "type": "NETWORK",
                "severity": "MEDIUM",
                "description": "Connected to a rare destination.",
                "mitre": ["TA0011 Command and Control"],
            },
        ],
        "observables": [
            {"type": "SHA1", "name": "file_sha1", "value": "da39a3ee5e6b4b0d3255bfef95601890afd80709"},
            {"type": "IP_ADDRESS", "name": "dst_ip", "value": "203.0.113.9"},
            {"type": "Domain", "name": "dst_domain", "value": "c2.example.test"},
        ],
        "process": {
            "command_line": "\"C:\\Users\\user1\\Downloads\\invoice.exe\" /silent",
            "parent": "explorer.exe",
            "user": "EXAMPLE\\user1",
            "file_path": "C:\\Users\\user1\\Downloads\\invoice.exe",
            "sha1": "da39a3ee5e6b4b0d3255bfef95601890afd80709",
            "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        },
        "purple_ai": {
            "status": "COMPLETED",
            "verdict": "TRUE_POSITIVE",
            "result": "The binary is packed and beacons to a rare host.",
            "timestamp": "2026-11-20T10:06:00.000Z",
        },
        "related_alerts": [{"id": "018e1efe-0000-7000-8000-000000000002", "name": "Suspicious script"}],
        "raw_data": "",
        "truncated": False,
    }


def test_purple_ai_false_positive_is_info(run_analyzer, mocked_api, load_fixture):
    body = load_fixture("edr_alert.json")
    body["data"]["aiInvestigations"][0]["verdict"] = "FALSE_POSITIVE"
    mocked_api.post(GQL_URL, json=body)

    output = run_analyzer(ID)

    assert tax("info", "PurpleAI", "FALSE_POSITIVE") in output["summary"]["taxonomies"]


def test_aws_alert_report(run_analyzer, mocked_api, load_fixture):
    mocked_api.post(GQL_URL, json=load_fixture("aws_alert.json"))

    output = run_analyzer(ID)

    assert output["success"] is True
    predicates = {t["predicate"]: t["value"] for t in output["summary"]["taxonomies"]}
    assert predicates["Product"] == "AWS GuardDuty"
    assert "PurpleAI" not in predicates
    assert "Confidence" not in predicates
    full = output["full"]
    assert full["process"] == {}
    assert full["raw_data"] == json.dumps(
        {"eventName": "ConsoleLogin", "sourceIPAddress": "198.51.100.23", "region": "us-east-1"},
        separators=(",", ":"),
    )
    assert full["observables"] == [{"type": "IP_ADDRESS", "name": "src_ip", "value": "198.51.100.23"}]
    assert full["assets"][0]["tags"] == ["account=123456789012"]
    assert full["purple_ai"] == {}


def test_not_found_is_safe(run_analyzer, mocked_api):
    mocked_api.post(
        GQL_URL,
        json={
            "data": {"alert": None, "aiInvestigations": []},
            "errors": [{"message": "Alert not found", "path": ["alert"]}],
        },
    )

    output = run_analyzer(ID)

    assert output["success"] is True
    assert output["summary"]["taxonomies"] == [tax("safe", "Found", "False")]
    assert output["full"] == {"query_type": "other", "found": False, **EMPTY, "truncated": False}


def test_purple_ai_error_nulls_data_then_retries_alert_only(run_analyzer, mocked_api, analyzer_class, load_fixture):
    body = load_fixture("edr_alert.json")
    del body["data"]["aiInvestigations"]
    mocked_api.post(
        GQL_URL, json={"data": None, "errors": [{"message": "license", "path": ["aiInvestigations"]}]}
    )
    mocked_api.post(GQL_URL, json=body)

    output = run_analyzer(ID)

    assert output["success"] is True
    assert output["full"]["purple_ai"] == {}
    assert output["full"]["found"] is True
    assert len(mocked_api.calls) == 2
    second = json.loads(mocked_api.calls[1].request.body)
    assert second == {"query": analyzer_class.ALERT_ONLY_QUERY, "variables": {"id": ID}}


def test_purple_ai_error_with_alert_present_is_ignored(run_analyzer, mocked_api, load_fixture):
    body = load_fixture("edr_alert.json")
    body["data"]["aiInvestigations"] = None
    body["errors"] = [{"message": "license", "path": ["aiInvestigations"]}]
    mocked_api.post(GQL_URL, json=body)

    output = run_analyzer(ID)

    assert output["success"] is True
    assert output["full"]["purple_ai"] == {}
    assert len(mocked_api.calls) == 1


@pytest.mark.parametrize("body", [{"data": None}, {}, {"data": {}}])
def test_missing_data_fails_the_job(run_analyzer, mocked_api, body):
    mocked_api.post(GQL_URL, json=body)

    output = run_analyzer(ID)

    assert output["success"] is False


def test_not_found_on_another_path_is_not_a_safe_result(run_analyzer, mocked_api):
    mocked_api.post(
        GQL_URL,
        json={"data": {"alert": None}, "errors": [{"message": "Thing not found", "path": ["aiInvestigations"]}]},
    )

    output = run_analyzer(ID)

    assert output["success"] is False


def test_purple_ai_in_progress_has_no_taxonomy(run_analyzer, mocked_api, load_fixture):
    body = load_fixture("edr_alert.json")
    body["data"]["aiInvestigations"] = [{"status": "IN_PROGRESS", "verdict": None, "result": None, "timestamp": None}]
    mocked_api.post(GQL_URL, json=body)

    output = run_analyzer(ID)

    assert "PurpleAI" not in [t["predicate"] for t in output["summary"]["taxonomies"]]
    assert output["full"]["purple_ai"]["status"] == "IN_PROGRESS"


def test_graphql_error_fails_without_token(run_analyzer, mocked_api):
    mocked_api.post(GQL_URL, json={"data": None, "errors": [{"message": "boom test-token"}]})

    output = run_analyzer(ID)

    assert output["success"] is False
    assert "test-token" not in str(output)


def test_alert_null_with_other_error_fails(run_analyzer, mocked_api):
    mocked_api.post(
        GQL_URL,
        json={"data": {"alert": None}, "errors": [{"message": "Internal failure", "path": ["alert"]}]},
    )

    output = run_analyzer(ID)

    assert output["success"] is False
    assert "Internal failure" in output["errorMessage"]


@pytest.mark.parametrize("bad_id", ['a"b', "x}y", "a b", "", "a" * 65])
def test_bad_alert_id_rejected(run_analyzer, mocked_api, bad_id):
    output = run_analyzer(bad_id)

    assert output["success"] is False
    assert len(mocked_api.calls) == 0


def test_caps_and_truncation(run_analyzer, mocked_api, load_fixture):
    body = load_fixture("edr_alert.json")
    alert = body["data"]["alert"]
    alert["process"]["cmdLine"] = "x" * 1500
    alert["rawData"] = {"blob": "y" * 50000}
    body["data"]["aiInvestigations"][0]["result"] = "z" * 2500
    template = alert["indicators"][0]
    alert["indicators"] = [
        {**copy.deepcopy(template), "eventTime": f"2026-11-20T11:00:{n % 60:02d}.{n:03d}Z", "observables": []}
        for n in range(60)
    ]
    mocked_api.post(GQL_URL, json=body)

    output = run_analyzer(ID)

    full = output["full"]
    assert len(full["process"]["command_line"]) == 1000
    assert len(full["raw_data"]) == 4000
    assert len(full["purple_ai"]["result"]) == 2000
    assert len(full["indicators"]) == 50
    assert full["truncated"] is True
    # The Indicators taxonomy counts the indicators kept in the report.
    assert tax("info", "Indicators", 50) in output["summary"]["taxonomies"]


def test_read_only_single_fixed_query(run_analyzer, mocked_api, analyzer_class, load_fixture):
    mocked_api.post(GQL_URL, json=load_fixture("edr_alert.json"))

    run_analyzer(ID)

    assert len(mocked_api.calls) == 1
    request = mocked_api.calls[0].request
    body = request.body.decode() if isinstance(request.body, bytes) else request.body
    assert request.method == "POST"
    assert request.url.endswith(analyzer_class.GRAPHQL_PATH)
    assert json.loads(body) == {"query": analyzer_class.QUERY, "variables": {"id": ID}}
    assert analyzer_class.ALERT_ONLY_QUERY.lstrip().startswith("query ")
    assert "mutation" not in analyzer_class.ALERT_ONLY_QUERY
    assert "aiInvestigations" not in analyzer_class.ALERT_ONLY_QUERY
    assert "mutation" not in body
    assert analyzer_class.QUERY.lstrip().startswith("query ")
    assert request.headers["Authorization"] == "ApiToken test-token"


def test_auth_failure_mentions_api_token_and_hides_it(run_analyzer, mocked_api):
    mocked_api.post(GQL_URL, status=401)

    output = run_analyzer(ID)

    assert output["success"] is False
    assert "API token" in output["errorMessage"]
    assert output["input"]["config"]["api_token"] == "REMOVED"


def test_forbidden_is_reported_as_auth_failure(run_analyzer, mocked_api):
    mocked_api.post(GQL_URL, status=403)

    output = run_analyzer(ID)

    assert output["success"] is False
    assert "HTTP 403" in output["errorMessage"]


def test_rate_limit_is_reported(run_analyzer, mocked_api):
    mocked_api.post(GQL_URL, status=429)

    output = run_analyzer(ID)

    assert output["success"] is False
    assert "rate limited" in output["errorMessage"]


def test_server_error_includes_status_and_body(run_analyzer, mocked_api):
    mocked_api.post(GQL_URL, status=500, body="upstream exploded")

    output = run_analyzer(ID)

    assert output["success"] is False
    assert "HTTP 500" in output["errorMessage"]
    assert "upstream exploded" in output["errorMessage"]


def test_timeout_names_the_service(run_analyzer, mocked_api):
    mocked_api.post(GQL_URL, body=requests.exceptions.ReadTimeout())

    output = run_analyzer(ID)

    assert output["success"] is False
    assert output["errorMessage"].startswith(f"{NS}: request timed out")


def test_non_json_response_fails(run_analyzer, mocked_api):
    mocked_api.post(GQL_URL, body="<html>proxy</html>", status=200)

    output = run_analyzer(ID)

    assert output["success"] is False
    assert "not JSON" in output["errorMessage"]


def test_unsupported_data_type(run_analyzer, mocked_api):
    output = run_analyzer("user@example.com", data_type="mail")

    assert output["success"] is False
    assert "not supported" in output["errorMessage"]


def test_tlp_above_max_is_rejected_before_any_request(run_analyzer, mocked_api):
    output = run_analyzer(ID, tlp=3)

    assert output["success"] is False
    assert "TLP" in output["errorMessage"]
    assert len(mocked_api.calls) == 0


def test_http_console_url_is_refused(run_analyzer, mocked_api):
    output = run_analyzer(ID, config={"url": "http://console.example.test"})

    assert output["success"] is False
    assert "https://" in output["errorMessage"]
    assert len(mocked_api.calls) == 0


def test_token_is_redacted_from_connection_errors(run_analyzer, mocked_api):
    mocked_api.post(GQL_URL, body=requests.exceptions.ConnectionError("failed, Authorization: test-token"))

    output = run_analyzer(ID)

    assert output["success"] is False
    assert "test-token" not in output["errorMessage"]
    assert "REMOVED" in output["errorMessage"]


def test_url_encoded_token_is_redacted(run_analyzer, mocked_api):
    mocked_api.post(GQL_URL, body=requests.exceptions.ConnectionError("failed, t=ab%2Bc%2Fd%3D"))

    output = run_analyzer(ID, config={"api_token": "ab+c/d="})

    assert output["success"] is False
    for form in ("ab+c/d=", "ab%2Bc%2Fd%3D"):
        assert form not in output["errorMessage"]


def test_token_is_redacted_from_error_bodies(run_analyzer, mocked_api):
    mocked_api.post(GQL_URL, status=500, body="bad request token=test-token")

    output = run_analyzer(ID)

    assert output["success"] is False
    assert "test-token" not in output["errorMessage"]


def test_every_declared_data_type_has_a_handler(flavor, analyzer_class):
    missing = set(flavor["dataTypeList"]) - set(analyzer_class.HANDLERS)
    assert not missing, f"No handler in HANDLERS for: {sorted(missing)}"
    broken = sorted(
        f"{data_type} -> {name}"
        for data_type, name in analyzer_class.HANDLERS.items()
        if not callable(getattr(analyzer_class, name, None))
    )
    assert not broken, f"HANDLERS entries without a callable method: {broken}"
