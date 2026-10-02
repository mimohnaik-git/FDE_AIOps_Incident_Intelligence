"""Normalize → redact → fingerprint → dedup → correlate → rules → advisory → persist."""

from datetime import UTC, datetime
from uuid import uuid4

from aiops.analysis import AnalysisFailure, MockAnalyzer, OpenRouterAnalyzer, validate_analysis
from aiops.models import (
    Incident,
    IncidentEvidence,
    IngestRequest,
    LLMState,
    RunMetrics,
    RunState,
    Severity,
    Status,
)
from aiops.rules import assess
from aiops.sanitize import digest, normalize
from aiops.store import Store


class Pipeline:
    def __init__(self, store: Store, window_seconds: int = 300):
        if not 1 <= window_seconds <= 3600:
            raise ValueError("invalid correlation window")
        self.store = store
        self.window_seconds = window_seconds

    def ingest(self, request: IngestRequest, analyzer=None) -> RunState:
        started = datetime.now(UTC)
        metrics = RunMetrics(events_received=len(request.events))
        touched: dict[str, Incident] = {}
        new_ids: set[str] = set()
        selected = analyzer
        if selected is None:
            selected = {"none": None, "mock": MockAnalyzer, "openrouter": OpenRouterAnalyzer}[
                request.analyzer
            ]
            selected = selected() if selected else None
        with self.store.lock, self.store.db:
            incidents = self.store.incidents()
            for raw in sorted(request.events, key=lambda item: item.timestamp):
                event = normalize(raw)
                severity, reason, routing = assess(event)
                if severity == Severity.P5:
                    metrics.noise_filtered += 1
                    metrics.llm_calls_avoided += 1
                    self.store.save_event(event, None, False)
                    continue
                if self.store.event_exists(event.event_id):
                    metrics.duplicates_removed += 1
                    metrics.llm_calls_avoided += 1
                    continue
                candidates = [
                    item
                    for item in incidents
                    if item.source == event.source
                    and item.component == event.component
                    and (
                        max(event.timestamp, item.last_seen) - min(event.timestamp, item.first_seen)
                    ).total_seconds()
                    <= self.window_seconds
                ]
                duplicate = next(
                    (item for item in candidates if event.fingerprint.value in item.fingerprints),
                    None,
                )
                incident = duplicate or next(
                    (
                        item
                        for item in candidates
                        if item.status in {Status.OPEN, Status.INVESTIGATING}
                    ),
                    None,
                )
                if duplicate:
                    metrics.duplicates_removed += 1
                    metrics.llm_calls_avoided += 1
                else:
                    metrics.events_retained += 1
                if incident is None:
                    incident = Incident(
                        incident_id=digest(f"incident|{event.event_id}"),
                        first_seen=event.timestamp,
                        last_seen=event.timestamp,
                        source=event.source,
                        component=event.component,
                        severity=severity,
                        severity_reason=reason,
                        event_count=1,
                        fingerprints=[event.fingerprint.value],
                        routing=routing,
                        evidence=[
                            IncidentEvidence(
                                event_id=event.event_id,
                                timestamp=event.timestamp,
                                snippet=event.message,
                                fingerprint=event.fingerprint.value,
                            )
                        ],
                        summary=f"{event.component}: {reason}",
                        diagnostic_next_steps=["Confirm impact and inspect sanitized evidence"],
                    )
                    incidents.append(incident)
                    new_ids.add(incident.incident_id)
                    metrics.incidents_formed += 1
                else:
                    incident.event_count += 1
                    incident.first_seen = min(incident.first_seen, event.timestamp)
                    incident.last_seen = max(incident.last_seen, event.timestamp)
                    metrics.correlated_event_count += 1
                    if not duplicate:
                        incident.fingerprints.append(event.fingerprint.value)
                        if len(incident.evidence) < 20:
                            incident.evidence.append(
                                IncidentEvidence(
                                    event_id=event.event_id,
                                    timestamp=event.timestamp,
                                    snippet=event.message,
                                    fingerprint=event.fingerprint.value,
                                )
                            )
                        metrics.llm_calls_avoided += 1
                    if severity.value < incident.severity.value:
                        incident.severity, incident.severity_reason = severity, reason
                        incident.summary = f"{event.component}: {reason}"
                    incident.routing.departments = sorted(
                        set(incident.routing.departments + routing.departments)
                    )
                    incident.routing.reason = "Deterministic component and matched event rules"
                touched[incident.incident_id] = incident
                self.store.save_incident(incident)
                self.store.save_event(event, incident.incident_id, bool(duplicate))
            for incident_id in sorted(new_ids):
                incident = touched[incident_id]
                if selected:
                    metrics.llm_calls += 1
                    try:
                        analysis = selected.analyze(incident.model_copy(deep=True))
                        # Enforce contract even for injected/custom adapters.
                        incident.analysis = validate_analysis(analysis.model_dump_json())
                        incident.llm_state = selected.state
                    except AnalysisFailure as error:
                        incident.llm_state = LLMState.FAILED
                        incident.failure = (
                            "invalid_model_output"
                            if error.code == "invalid_model_output"
                            else "model_unavailable"
                        )
                    except Exception:
                        # Never forward arbitrary exception text, including request headers.
                        incident.llm_state = LLMState.FAILED
                        incident.failure = "model_unavailable"
                else:
                    metrics.llm_calls_avoided += 1
                self.store.save_incident(incident)
            run = RunState(
                run_id=uuid4().hex,
                started_at=started,
                completed_at=datetime.now(UTC),
                metrics=metrics,
                incident_ids=sorted(touched),
            )
            self.store.save_run(run)
        return run
