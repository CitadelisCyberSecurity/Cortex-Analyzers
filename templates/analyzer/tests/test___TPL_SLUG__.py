"""Tests for the __TPL_NAME__ analyzer.

They run the analyzer exactly as Cortex does (see conftest.py) with all HTTP
mocked, so no network access or API key is needed. When you replace the
example API logic, record a real response into tests/fixtures/ and update
these tests to match.
"""

import requests

IP = "198.51.100.7"
NS = "__TPL_NAME__"


def ip_url(analyzer_class):
    return f"{analyzer_class.BASE_URL}/ip/{IP}"


def test_found_reports_taxonomies_and_artifacts(run_analyzer, mocked_api, analyzer_class, load_fixture):
    mocked_api.get(ip_url(analyzer_class), json=load_fixture("sample_response.json"))

    output = run_analyzer(IP)

    assert output["success"] is True
    assert output["summary"]["taxonomies"] == [
        {"level": "malicious", "namespace": NS, "predicate": "Score", "value": 87},
        {"level": "info", "namespace": NS, "predicate": "Reports", "value": 412},
    ]
    assert output["artifacts"] == [
        {"dataType": "domain", "data": "example-hosting.net", "tags": [NS]},
        {"dataType": "fqdn", "data": "scanner01.example-hosting.net", "tags": [NS]},
    ]
    assert output["full"]["found"] is True
    assert mocked_api.calls[0].request.headers["Authorization"] == "Bearer test-key"


def test_not_found_is_a_safe_result(run_analyzer, mocked_api, analyzer_class):
    mocked_api.get(ip_url(analyzer_class), status=404)

    output = run_analyzer(IP)

    assert output["success"] is True
    assert output["summary"]["taxonomies"] == [
        {"level": "safe", "namespace": NS, "predicate": "Found", "value": "False"},
    ]
    assert output["artifacts"] == []


def test_auth_failure_mentions_api_key_and_hides_it(run_analyzer, mocked_api, analyzer_class):
    mocked_api.get(ip_url(analyzer_class), status=401)

    output = run_analyzer(IP)

    assert output["success"] is False
    assert "API key" in output["errorMessage"]
    assert output["input"]["config"]["key"] == "REMOVED"


def test_rate_limit_is_reported(run_analyzer, mocked_api, analyzer_class):
    mocked_api.get(ip_url(analyzer_class), status=429)

    output = run_analyzer(IP)

    assert output["success"] is False
    assert "rate limited" in output["errorMessage"]


def test_server_error_includes_status_and_body(run_analyzer, mocked_api, analyzer_class):
    mocked_api.get(ip_url(analyzer_class), status=500, body="upstream exploded")

    output = run_analyzer(IP)

    assert output["success"] is False
    assert "HTTP 500" in output["errorMessage"]
    assert "upstream exploded" in output["errorMessage"]


def test_timeout_names_the_service(run_analyzer, mocked_api, analyzer_class):
    mocked_api.get(ip_url(analyzer_class), body=requests.exceptions.ReadTimeout())

    output = run_analyzer(IP)

    assert output["success"] is False
    assert output["errorMessage"].startswith(f"{NS}: request timed out")


def test_unsupported_data_type(run_analyzer, mocked_api):
    output = run_analyzer("user@example.com", data_type="mail")

    assert output["success"] is False
    assert "not supported" in output["errorMessage"]


def test_tlp_above_max_is_rejected_before_any_request(run_analyzer, mocked_api):
    output = run_analyzer(IP, tlp=3)

    assert output["success"] is False
    assert "TLP" in output["errorMessage"]
    assert len(mocked_api.calls) == 0


def test_summary_error_fails_the_job(run_analyzer, mocked_api, analyzer_class):
    mocked_api.get(ip_url(analyzer_class), json={"score": "high"})

    output = run_analyzer(IP)

    assert output["success"] is False
    assert "Unexpected Error" in output["errorMessage"]


def test_api_key_is_redacted_from_connection_errors(run_analyzer, mocked_api, analyzer_class):
    mocked_api.get(
        ip_url(analyzer_class),
        body=requests.exceptions.ConnectionError("Max retries exceeded with url: /ip/x?key=test-key"),
    )

    output = run_analyzer(IP)

    assert output["success"] is False
    assert "test-key" not in output["errorMessage"]
    assert "REMOVED" in output["errorMessage"]


def test_api_key_is_redacted_from_error_bodies(run_analyzer, mocked_api, analyzer_class):
    mocked_api.get(ip_url(analyzer_class), status=500, body="bad request key=test-key")

    output = run_analyzer(IP)

    assert output["success"] is False
    assert "test-key" not in output["errorMessage"]


def test_every_declared_data_type_has_a_handler(flavor, analyzer_class):
    missing = set(flavor["dataTypeList"]) - set(analyzer_class.HANDLERS)
    assert not missing, f"No handler in HANDLERS for: {sorted(missing)}"
