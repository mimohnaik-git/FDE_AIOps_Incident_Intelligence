"""Frozen offline contract evaluation, not production accuracy measurement."""

import json
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import patch

import httpx

from aiops.analysis import OpenRouterAnalyzer, payload
from aiops.collectors import SystemLogCollector
from aiops.models import Incident, IngestRequest, RawLogEvent
from aiops.offline import network_guard
from aiops.pipeline import Pipeline
from aiops.store import Store


def evaluate() -> dict:
    cases = json.loads(Path("evaluation/cases.json").read_text(encoding="utf-8"))
    totals = {
        "events_received": 0,
        "duplicates_removed": 0,
        "incidents": 0,
        "schema_valid_incidents": 0,
        "severity_matches": 0,
        "routing_matches": 0,
        "redaction_failures": 0,
        "expected_incident_count_matches": 0,
        "correlation_correct_cases": 0,
        "invalid_model_outputs_rejected": 0,
        "model_unavailable_handled": 0,
        "collector_failures_handled": 0,
        "unexpected_llm_calls": 0,
        "unexpected_network_attempts": 0,
        "workflow_completed": 0,
        "workflow_failed": 0,
    }
    failures = []
    for case in cases:
        store = Store(":memory:")
        selected = None
        try:
            start = datetime(2026, 1, 1, tzinfo=UTC)
            events = [
                RawLogEvent(component=c, message=m, timestamp=start + timedelta(seconds=t))
                for c, m, t in case["events"]
            ]
            if case.get("failure") == "collector":
                with (
                    patch("aiops.collectors.platform.system", return_value="Linux"),
                    patch.object(
                        SystemLogCollector,
                        "_launch",
                        side_effect=OSError("synthetic process start failure"),
                    ),
                ):
                    result = SystemLogCollector().collect()
                assert result.error == "unavailable" and not result.events
                totals["collector_failures_handled"] += 1
            if case.get("failure") == "malformed":
                transport = httpx.MockTransport(
                    lambda request: httpx.Response(
                        200, json={"choices": [{"message": {"content": "{invalid"}}]}
                    )
                )
                selected = OpenRouterAnalyzer(httpx.Client(transport=transport))
            if case.get("failure") == "unavailable":
                selected = OpenRouterAnalyzer()
            with (
                patch.dict(
                    os.environ,
                    {"OPENROUTER_API_KEY": "runtimeFenceLabelQ9"}
                    if case.get("failure") != "unavailable"
                    else {},
                    clear=True,
                ),
                network_guard() as attempts,
            ):
                run = Pipeline(store).ingest(
                    IngestRequest(events=events, analyzer=case.get("analysis", "none")),
                    analyzer=selected,
                )
                totals["unexpected_network_attempts"] += len(attempts)
                assert not attempts, "unexpected application network attempt"
            incidents = sorted(store.incidents(), key=lambda i: (i.component, i.first_seen))
            expected = sorted(case["labels"], key=lambda row: row[0])
            totals["events_received"] += run.metrics.events_received
            totals["duplicates_removed"] += run.metrics.duplicates_removed
            totals["incidents"] += len(incidents)
            count_ok = len(incidents) == len(expected)
            totals["expected_incident_count_matches"] += int(count_ok)
            assert count_ok, "incident count mismatch"
            correlation_ok = run.metrics.correlated_event_count == case["correlated"]
            for incident, label in zip(incidents, expected, strict=True):
                Incident.model_validate_json(incident.model_dump_json())
                totals["schema_valid_incidents"] += 1
                totals["severity_matches"] += int(incident.severity == label[1])
                totals["routing_matches"] += int(incident.routing.departments == [label[2]])
                assert incident.severity == label[1], "severity mismatch"
                assert incident.routing.departments == [label[2]], "routing mismatch"
                correlation_ok &= (
                    incident.component == label[0] and incident.event_count == label[3]
                )
                persisted = incident.model_dump_json() + payload(incident)
                persisted += "".join(
                    event.model_dump_json() for event in store.events(incident.incident_id)
                )
                for forbidden in case.get("forbidden", []):
                    totals["redaction_failures"] += int(forbidden in persisted)
                    assert forbidden not in persisted, "redaction failure"
            totals["correlation_correct_cases"] += int(correlation_ok)
            assert correlation_ok, "correlation mismatch"
            assert run.metrics.duplicates_removed == case["duplicates"], "dedup mismatch"
            unexpected = abs(run.metrics.llm_calls - case.get("calls", 0))
            totals["unexpected_llm_calls"] += unexpected
            assert unexpected == 0, "unexpected analyzer call"
            if case.get("failure") == "malformed":
                assert incidents[0].failure == "invalid_model_output" and not incidents[0].analysis
                totals["invalid_model_outputs_rejected"] += 1
            if case.get("failure") == "unavailable":
                assert incidents[0].failure == "model_unavailable" and not incidents[0].analysis
                totals["model_unavailable_handled"] += 1
            totals["workflow_completed"] += 1
        except (AssertionError, ValueError) as error:
            failures.append({"case": case["name"], "error": type(error).__name__})
            totals["workflow_failed"] += 1
        finally:
            if isinstance(selected, OpenRouterAnalyzer) and selected.client:
                selected.client.close()
            store.close()
    count = totals["incidents"]
    return {
        "dataset": "frozen-offline-contract-v1",
        "scenarios": len(cases),
        **totals,
        "schema_validity": totals["schema_valid_incidents"] / count if count else 1,
        "severity_agreement": totals["severity_matches"] / count if count else 1,
        "routing_agreement": totals["routing_matches"] / count if count else 1,
        "deduplication_rate": totals["duplicates_removed"] / totals["events_received"],
        "failures": failures,
    }


if __name__ == "__main__":
    report = evaluate()
    print(json.dumps(report, indent=2))
    raise SystemExit(int(bool(report["failures"])))
