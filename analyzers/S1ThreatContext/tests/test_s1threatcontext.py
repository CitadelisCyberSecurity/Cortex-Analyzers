"""Tests for the S1ThreatContext analyzer.

They run the analyzer exactly as Cortex does (see conftest.py) with all HTTP
mocked, so no console or token is needed. Fixtures are synthetic: no real
hostnames, users, IPs or sites.
"""

import requests

THREAT_ID = "1234567890123456789"
NS = "S1ThreatContext"
API = "https://console.example.test/web/api/v2.1"
THREATS_URL = f"{API}/threats"
EVENTS_URL = f"{API}/threats/{THREAT_ID}/explore/events"
EMPTY_LISTS = {"processes": [], "network": [], "dns": [], "files": [], "registry": []}


def process_event(n):
    return {"objectType": "process", "createdAt": f"2026-11-20T10:00:{n:02d}.000Z", "processName": f"p{n}.exe"}


def test_found_threat_with_events(run_analyzer, mocked_api, load_fixture):
    mocked_api.get(THREATS_URL, json=load_fixture("threat.json"))
    mocked_api.get(EVENTS_URL, json=load_fixture("events.json"))

    output = run_analyzer(THREAT_ID)

    assert output["success"] is True
    assert output["summary"]["taxonomies"] == [
        {"level": "info", "namespace": NS, "predicate": "Found", "value": "True"},
        {"level": "malicious", "namespace": NS, "predicate": "Confidence", "value": "malicious"},
        {"level": "info", "namespace": NS, "predicate": "Verdict", "value": "undefined"},
        {"level": "info", "namespace": NS, "predicate": "Mitigation", "value": "mitigated"},
        {"level": "info", "namespace": NS, "predicate": "Events", "value": 8},
    ]
    assert output["full"] == {
        "query_type": "other",
        "found": True,
        "threat": {
            "id": THREAT_ID,
            "name": "invoice.exe",
            "classification": "Trojan",
            "confidence": "malicious",
            "analyst_verdict": "undefined",
            "mitigation_status": "mitigated",
            "incident_status": "unresolved",
            "storyline": "ABCDEF0123456789",
            "file_path": "\\Device\\HarddiskVolume3\\Users\\user1\\Downloads\\invoice.exe",
            "sha1": "da39a3ee5e6b4b0d3255bfef95601890afd80709",
            "originator_process": "explorer.exe",
            "command_line": "\"C:\\Users\\user1\\Downloads\\invoice.exe\" /silent",
            "process_user": "EXAMPLE\\user1",
            "endpoint": "WS-0001",
            "os": "Windows 11 Pro",
            "site": "Example Site",
        },
        "processes": [
            {"time": "2026-11-20T10:00:01.000Z", "name": "invoice.exe", "pid": "3880", "parent": "explorer.exe",
             "user": "EXAMPLE\\user1", "command_line": "invoice.exe /silent",
             "sha1": "da39a3ee5e6b4b0d3255bfef95601890afd80709"},
            {"time": "2026-11-20T10:00:05.000Z", "name": "cmd.exe", "pid": "4120", "parent": "invoice.exe",
             "user": "EXAMPLE\\user1", "command_line": "cmd.exe /c whoami",
             "sha1": "1111111111111111111111111111111111111111"},
        ],
        "network": [
            {"time": "2026-11-20T10:00:07.000Z", "process": "invoice.exe", "direction": "OUTGOING",
             "remote_ip": "203.0.113.5", "remote_port": 443},
            {"time": "2026-11-20T10:00:08.000Z", "process": "invoice.exe", "direction": "INCOMING",
             "remote_ip": "198.51.100.9", "remote_port": 4444},
        ],
        "dns": [
            {"time": "2026-11-20T10:00:06.000Z", "process": "invoice.exe", "query": "c2.example.test",
             "response": "type: 1 203.0.113.5;"},
        ],
        "files": [
            {"time": "2026-11-20T10:00:09.000Z", "process": "invoice.exe", "action": "create",
             "path": "C:\\Users\\user1\\AppData\\Roaming\\svc.dll", "sha1": "2222222222222222222222222222222222222222"},
            {"time": "2026-11-20T10:00:10.000Z", "process": "invoice.exe", "action": "delete",
             "path": "C:\\Users\\user1\\Downloads\\invoice.exe"},
        ],
        "registry": [
            {"time": "2026-11-20T10:00:11.000Z", "process": "invoice.exe", "action": "Registry Value Modified",
             "key": "MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\svc"},
        ],
        "truncated": False,
    }
    assert output["artifacts"] == []

    threats_req, events_req = (c.request for c in mocked_api.calls)
    assert threats_req.headers["Authorization"] == "ApiToken test-token"
    assert threats_req.headers["User-Agent"].startswith("citadelis-cortex-")
    assert threats_req.params == {"ids": THREAT_ID}
    assert events_req.params["eventTypes"] == "process,file,ip,dns,registry"
    assert events_req.params["limit"] == "50"


def test_unknown_threat_is_safe_not_found(run_analyzer, mocked_api):
    mocked_api.get(THREATS_URL, json={"data": [], "pagination": {}})

    output = run_analyzer(THREAT_ID)

    assert output["success"] is True
    assert output["summary"]["taxonomies"] == [
        {"level": "safe", "namespace": NS, "predicate": "Found", "value": "False"},
    ]
    assert output["full"] == {"query_type": "other", "found": False, "threat": {}, **EMPTY_LISTS, "truncated": False}


def test_non_numeric_id_is_rejected_without_leaking_token(run_analyzer, mocked_api):
    for bad in ("abc", "123-456", "12 34", ""):
        output = run_analyzer(bad)

        assert output["success"] is False
        assert "numeric" in output["errorMessage"]
        assert "test-token" not in str(output)
    assert len(mocked_api.calls) == 0


def test_pagination_stops_at_max_events_and_truncates(run_analyzer, mocked_api, load_fixture):
    mocked_api.get(THREATS_URL, json=load_fixture("threat.json"))
    mocked_api.get(EVENTS_URL, json={"data": [process_event(n) for n in range(3)], "pagination": {"nextCursor": "c1"}})
    mocked_api.get(EVENTS_URL, json={"data": [process_event(n) for n in range(3, 5)], "pagination": {"nextCursor": "c2"}})

    output = run_analyzer(THREAT_ID, config={"max_events": 5})

    assert output["success"] is True
    assert len(output["full"]["processes"]) == 5
    assert output["full"]["truncated"] is True
    assert output["summary"]["taxonomies"][-1] == {"level": "info", "namespace": NS, "predicate": "Events", "value": 5}
    first, second = (c.request for c in mocked_api.calls[1:])
    assert first.params["limit"] == "5" and "cursor" not in first.params
    assert second.params["limit"] == "2" and second.params["cursor"] == "c1"


def test_last_page_without_cursor_is_not_truncated(run_analyzer, mocked_api, load_fixture):
    mocked_api.get(THREATS_URL, json=load_fixture("threat.json"))
    mocked_api.get(EVENTS_URL, json={"data": [process_event(n) for n in range(5)], "pagination": {"nextCursor": None}})

    output = run_analyzer(THREAT_ID, config={"max_events": 5})

    assert output["full"]["truncated"] is False


def test_long_command_line_is_cut_to_1000(run_analyzer, mocked_api, load_fixture):
    threat = load_fixture("threat.json")
    threat["data"][0]["threatInfo"]["maliciousProcessArguments"] = "A" * 1500
    long_event = dict(process_event(1), processCmd="B" * 1500, processName="x" * 700)
    mocked_api.get(THREATS_URL, json=threat)
    mocked_api.get(EVENTS_URL, json={"data": [long_event]})

    output = run_analyzer(THREAT_ID)

    assert output["full"]["threat"]["command_line"] == "A" * 1000
    assert output["full"]["processes"][0]["command_line"] == "B" * 1000
    assert output["full"]["processes"][0]["name"] == "x" * 500
    assert output["full"]["truncated"] is True


def test_events_endpoint_404_still_succeeds(run_analyzer, mocked_api, load_fixture):
    mocked_api.get(THREATS_URL, json=load_fixture("threat.json"))
    mocked_api.get(EVENTS_URL, status=404)

    output = run_analyzer(THREAT_ID)

    assert output["success"] is True
    assert output["full"]["threat"]["id"] == THREAT_ID
    assert {k: output["full"][k] for k in EMPTY_LISTS} == EMPTY_LISTS
    assert output["summary"]["taxonomies"][-1] == {"level": "info", "namespace": NS, "predicate": "Events", "value": 0}


def test_events_endpoint_empty_still_succeeds(run_analyzer, mocked_api, load_fixture):
    mocked_api.get(THREATS_URL, json=load_fixture("threat.json"))
    mocked_api.get(EVENTS_URL, json={"data": [], "pagination": {"nextCursor": None}})

    output = run_analyzer(THREAT_ID)

    assert output["success"] is True
    assert output["summary"]["taxonomies"][-1]["value"] == 0


def test_only_get_requests_are_made(run_analyzer, mocked_api, load_fixture):
    mocked_api.get(THREATS_URL, json=load_fixture("threat.json"))
    mocked_api.get(EVENTS_URL, json=load_fixture("events.json"))

    run_analyzer(THREAT_ID)

    assert mocked_api.calls
    assert {c.request.method for c in mocked_api.calls} == {"GET"}


def test_suspicious_confidence_level(run_analyzer, mocked_api, load_fixture):
    threat = load_fixture("threat.json")
    threat["data"][0]["threatInfo"]["confidenceLevel"] = "suspicious"
    mocked_api.get(THREATS_URL, json=threat)
    mocked_api.get(EVENTS_URL, json={"data": []})

    output = run_analyzer(THREAT_ID)

    assert output["summary"]["taxonomies"][1] == {
        "level": "suspicious", "namespace": NS, "predicate": "Confidence", "value": "suspicious",
    }


def test_plain_http_console_url_is_refused(run_analyzer, mocked_api):
    output = run_analyzer(THREAT_ID, config={"url": "http://console.example.test"})

    assert output["success"] is False
    assert "https://" in output["errorMessage"]
    assert len(mocked_api.calls) == 0


def test_auth_failure_mentions_token_and_hides_it(run_analyzer, mocked_api):
    mocked_api.get(THREATS_URL, status=401)

    output = run_analyzer(THREAT_ID)

    assert output["success"] is False
    assert "API token" in output["errorMessage"]
    assert output["input"]["config"]["api_token"] == "REMOVED"


def test_rate_limit_is_reported(run_analyzer, mocked_api):
    mocked_api.get(THREATS_URL, status=429)

    output = run_analyzer(THREAT_ID)

    assert output["success"] is False
    assert "rate limited" in output["errorMessage"]


def test_server_error_includes_status_and_body(run_analyzer, mocked_api):
    mocked_api.get(THREATS_URL, status=500, body="upstream exploded")

    output = run_analyzer(THREAT_ID)

    assert output["success"] is False
    assert "HTTP 500" in output["errorMessage"]
    assert "upstream exploded" in output["errorMessage"]


def test_timeout_names_the_service(run_analyzer, mocked_api):
    mocked_api.get(THREATS_URL, body=requests.exceptions.ReadTimeout())

    output = run_analyzer(THREAT_ID)

    assert output["success"] is False
    assert output["errorMessage"].startswith(f"{NS}: request timed out")


def test_unsupported_data_type(run_analyzer, mocked_api):
    output = run_analyzer("198.51.100.7", data_type="ip")

    assert output["success"] is False
    assert "not supported" in output["errorMessage"]


def test_tlp_above_max_is_rejected_before_any_request(run_analyzer, mocked_api):
    output = run_analyzer(THREAT_ID, tlp=3)

    assert output["success"] is False
    assert "TLP" in output["errorMessage"]
    assert len(mocked_api.calls) == 0


def test_token_is_redacted_from_connection_errors(run_analyzer, mocked_api):
    mocked_api.get(THREATS_URL, body=requests.exceptions.ConnectionError("failed with ApiToken test-token"))

    output = run_analyzer(THREAT_ID)

    assert output["success"] is False
    assert "test-token" not in output["errorMessage"]
    assert "REMOVED" in output["errorMessage"]


def test_url_encoded_token_is_redacted(run_analyzer, mocked_api):
    mocked_api.get(THREATS_URL, body=requests.exceptions.ConnectionError("failed: ab%2Bc%2Fd%3D"))

    output = run_analyzer(THREAT_ID, config={"api_token": "ab+c/d="})

    assert output["success"] is False
    for form in ("ab+c/d=", "ab%2Bc%2Fd%3D"):
        assert form not in output["errorMessage"]


def test_token_is_redacted_from_error_bodies(run_analyzer, mocked_api):
    mocked_api.get(THREATS_URL, status=500, body="bad request token=test-token")

    output = run_analyzer(THREAT_ID)

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
