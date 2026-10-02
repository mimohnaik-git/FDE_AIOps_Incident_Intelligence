import json
import sys
from unittest.mock import Mock

import httpx
import pytest
from fastapi.testclient import TestClient

from aiops.analysis import AnalysisFailure, OpenRouterAnalyzer, validate_analysis
from aiops.api import create_app
from aiops.collectors import SystemLogCollector
from aiops.evaluate import evaluate
from aiops.models import CollectionResult, IngestRequest
from aiops.pipeline import Pipeline
from aiops.store import Store
from tests.test_pipeline import event


def incident():
    store = Store(":memory:")
    Pipeline(store).ingest(IngestRequest(events=[event()]))
    result = store.incidents()[0]
    store.close()
    return result


@pytest.mark.parametrize(
    "content",
    [
        "not json",
        "{}",
        '{"summary":"x","severity":"P0"}',
        json.dumps(
            {
                "summary": "x",
                "likely_causes": [],
                "diagnostic_next_steps": ["check"],
                "suggested_departments": ["made_up"],
                "confidence": 0.5,
                "limitations": ["test"],
            }
        ),
        json.dumps(
            {
                "summary": "x",
                "likely_causes": [],
                "diagnostic_next_steps": ["check"],
                "suggested_departments": ["database"],
                "confidence": 1.1,
                "limitations": ["test"],
            }
        ),
    ],
)
def test_malformed_analysis_rejected(content):
    with pytest.raises(AnalysisFailure, match="invalid_model_output"):
        validate_analysis(content)


def test_no_key_fails_without_network():
    with pytest.raises(AnalysisFailure, match="model_unavailable"):
        OpenRouterAnalyzer().analyze(incident())


def test_http_success_redaction_and_prompt_contract(monkeypatch):
    monkeypatch.setenv("OPENROUTER_API_KEY", "fixtureApiKeyOnly")
    monkeypatch.setenv("OPENROUTER_MODEL", "test/model")
    sent = []

    def handler(request):
        body = json.loads(request.content)
        sent.append(body)
        assert "fixtureApiKeyOnly" not in request.content.decode()
        assert "tools" not in body and body["model"] == "test/model"
        content = json.dumps(
            {
                "summary": "password=fixtureOutputSecret",
                "likely_causes": [],
                "diagnostic_next_steps": ["Operator review"],
                "suggested_departments": ["database"],
                "confidence": 0.5,
                "limitations": ["Advisory only"],
            }
        )
        return httpx.Response(200, json={"choices": [{"message": {"content": content}}]})

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        result = OpenRouterAnalyzer(client).analyze(incident())
    assert "fixtureOutputSecret" not in result.summary and len(sent) == 1


@pytest.mark.parametrize(
    "mode,expected,calls",
    [
        ("timeout", "model_unavailable", 2),
        ("http", "model_unavailable", 1),
        ("missing", "invalid_model_output", 1),
        ("malformed", "invalid_model_output", 1),
        ("oversize", "invalid_model_output", 1),
    ],
)
def test_http_failures_safe(monkeypatch, mode, expected, calls):
    monkeypatch.setenv("OPENROUTER_API_KEY", "fixtureApiKeyOnly")
    seen = []

    def handler(request):
        seen.append(request)
        if mode == "timeout":
            raise httpx.ReadTimeout("fixtureApiKeyOnly", request=request)
        if mode == "http":
            return httpx.Response(401, text="fixtureApiKeyOnly")
        if mode == "oversize":
            return httpx.Response(200, content=b"x" * 65000)
        return httpx.Response(
            200, json={} if mode == "missing" else {"choices": [{"message": {"content": "oops"}}]}
        )

    store = Store(":memory:")
    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        run = Pipeline(store).ingest(
            IngestRequest(events=[event()]), analyzer=OpenRouterAnalyzer(client)
        )
    result = store.incidents()[0]
    assert result.failure == expected and result.analysis is None
    assert result.severity == "P0" and len(seen) == calls
    assert "fixtureApiKeyOnly" not in result.model_dump_json() + run.model_dump_json()
    store.close()


def test_api_demo_schemas_lifecycle_and_errors(tmp_path):
    with TestClient(create_app(str(tmp_path / "api.db"))) as client:
        assert client.get("/health").json()["analysis_default"] == "none"
        assert client.get("/incidents").json() == []
        run = client.post("/demo").json()
        assert run["metrics"]["incidents_formed"] == 3 and run["metrics"]["llm_calls"] == 0
        incidents = client.get("/incidents").json()
        identifier = incidents[0]["incident_id"]
        assert client.get(f"/incidents/{identifier}").status_code == 200
        assert client.get(f"/incidents/{identifier}/events").json()
        assert (
            client.patch(f"/incidents/{identifier}/status", json={"status": "resolved"}).status_code
            == 200
        )
        assert (
            client.patch(
                f"/incidents/{identifier}/status", json={"status": "investigating"}
            ).status_code
            == 409
        )
        assert client.get("/incidents/missing").status_code == 404
        assert client.post("/collect/system").status_code == 403
        bad = client.post(
            "/events/ingest", json={"events": [{"message": "password=fixturePrivate"}]}
        )
        assert bad.status_code == 422 and "fixturePrivate" not in bad.text
        replay = client.post("/demo").json()
        assert replay["metrics"]["llm_calls"] == replay["metrics"]["incidents_formed"] == 0
        assert len(client.get("/runs").json()) == 2
        assert "Incident queue" in client.get("/").text
        assert client.post("/events/ingest", content=b"x" * 2_500_001).status_code == 413


def test_api_explicit_collector_sanitizes_response(tmp_path, monkeypatch):
    collector = Mock(return_value=CollectionResult(events=[event("password=fixturePrivate")]))
    monkeypatch.setattr(SystemLogCollector, "collect", collector)
    with TestClient(
        create_app(str(tmp_path / "collect.db"), allow_system_collection=True)
    ) as client:
        assert collector.call_count == 0
        response = client.post("/collect/system")
        assert response.json()["events"] == [] and "fixturePrivate" not in response.text
        assert "fixturePrivate" not in client.get("/incidents").text
        collector.return_value = CollectionResult(error="command_failed")
        assert client.post("/collect/system").json()["error"] == "command_failed"
        assert client.get("/runs").json()[0]["status"] == "collection_failed"


@pytest.mark.parametrize(
    "system,first", [("Linux", "journalctl"), ("Darwin", "log"), ("Windows", "wevtutil")]
)
def test_collector_commands(monkeypatch, system, first):
    monkeypatch.setattr("aiops.collectors.platform.system", lambda: system)
    captured = []
    monkeypatch.setattr(
        SystemLogCollector, "_read", lambda self, cmd: captured.append(cmd) or CollectionResult()
    )
    assert SystemLogCollector().collect().error is None
    assert captured[0][0] == first


def test_collector_error_and_output_bounds(monkeypatch):
    collector = SystemLogCollector()
    assert collector._read(["nonexistent-aiops-fixture-command"]).error == "unavailable"
    assert collector._read([sys.executable, "-c", "raise SystemExit(1)"]).error == "command_failed"
    result = collector._read([sys.executable, "-c", "print('lease renewal recorded')"])
    assert result.events[0].message == "lease renewal recorded"
    result = collector._read([sys.executable, "-c", "print('x' * 200000)"])
    assert result.truncated and len(result.events) <= 500
    monkeypatch.setattr("aiops.collectors.platform.system", lambda: "unknown")
    assert collector.collect().error == "unsupported_os"
    with pytest.raises(ValueError):
        SystemLogCollector(minutes=100)


def test_collector_timeout(monkeypatch):
    import asyncio

    class HangingProcess:
        returncode = None

        def __init__(self):
            self.stdout = None
            self.killed = False
            self.wait_count = 0

        async def wait(self):
            self.wait_count += 1
            if self.wait_count == 1:
                await asyncio.Event().wait()
            self.returncode = -9

        def kill(self):
            self.killed = True

    process = HangingProcess()

    async def launch(command):
        process.stdout = asyncio.StreamReader()
        return process

    monkeypatch.setattr(SystemLogCollector, "_launch", lambda self, command: launch(command))
    monkeypatch.setattr(SystemLogCollector, "_DEADLINE_SECONDS", 0.01)
    assert SystemLogCollector()._read(["fixture"]).error == "timeout"
    assert process.killed


def test_frozen_offline_evaluation():
    report = evaluate()
    assert report["workflow_failed"] == 0, report
    assert (
        report["schema_validity"]
        == report["severity_agreement"]
        == report["routing_agreement"]
        == 1
    )
    assert report["unexpected_llm_calls"] == report["redaction_failures"] == 0


def test_collector_failure_contract():
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        CollectionResult(error="command_failed", events=[event()])
