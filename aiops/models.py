"""Validated domain contracts. P0 is highest priority, P5 is debug/noise."""

from datetime import datetime
from enum import StrEnum
from typing import Annotated, Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    field_validator,
    model_validator,
)

Text = Annotated[str, StringConstraints(min_length=1, max_length=4096)]
Label = Annotated[str, StringConstraints(pattern=r"^[a-zA-Z0-9_.:/-]{1,80}$")]
Identifier = Annotated[str, StringConstraints(pattern=r"^[a-f0-9]{32,64}$")]


class Contract(BaseModel):
    model_config = ConfigDict(extra="forbid", validate_assignment=True)


class Severity(StrEnum):
    P0 = "P0"  # outage / data corruption
    P1 = "P1"  # major degradation / imminent failure
    P2 = "P2"  # partial impairment
    P3 = "P3"  # warning
    P4 = "P4"  # informational
    P5 = "P5"  # debug / routine noise


class Department(StrEnum):
    APPLICATION = "application"
    NETWORK = "network"
    INFRASTRUCTURE = "infrastructure"
    SYSTEM_ADMIN = "system_admin"
    DATABASE = "database"
    SECURITY = "security"


class Status(StrEnum):
    OPEN = "open"
    INVESTIGATING = "investigating"
    RESOLVED = "resolved"
    SUPPRESSED = "suppressed"


class LLMState(StrEnum):
    NOT_REQUESTED = "not_requested"
    MOCK = "mock"
    SUCCEEDED = "succeeded"
    FAILED = "failed"


class RawLogEvent(Contract):
    timestamp: datetime
    source: Label = "synthetic"
    component: Label = "application"
    message: Text

    @field_validator("timestamp")
    @classmethod
    def aware_timestamp(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("timestamp must include timezone")
        return value


class RedactionResult(Contract):
    text: Text
    replacements: dict[str, int] = Field(default_factory=dict)
    policy: Literal["demo-v1"] = "demo-v1"


class EventFingerprint(Contract):
    value: Identifier
    signature: Text
    algorithm: Literal["sha256-v1"] = "sha256-v1"


class NormalizedEvent(RawLogEvent):
    event_id: Identifier
    fingerprint: EventFingerprint
    redaction: RedactionResult


class IncidentEvidence(Contract):
    event_id: Identifier
    timestamp: datetime
    snippet: Text
    fingerprint: Identifier
    redaction_policy: Literal["demo-v1"] = "demo-v1"


class RoutingDecision(Contract):
    departments: list[Department] = Field(min_length=1, max_length=6)
    reason: Text
    method: Literal["deterministic"] = "deterministic"


class IncidentAnalysis(Contract):
    summary: Text
    likely_causes: list[Text] = Field(max_length=8)
    diagnostic_next_steps: list[Text] = Field(min_length=1, max_length=8)
    suggested_departments: list[Department] = Field(min_length=1, max_length=6)
    confidence: float = Field(ge=0, le=1, strict=True)
    limitations: list[Text] = Field(min_length=1, max_length=8)


class Incident(Contract):
    incident_id: Identifier
    first_seen: datetime
    last_seen: datetime
    source: Label
    component: Label
    severity: Severity
    severity_reason: Text
    status: Status = Status.OPEN
    event_count: int = Field(ge=1, strict=True)
    fingerprints: list[Identifier] = Field(min_length=1)
    routing: RoutingDecision
    evidence: list[IncidentEvidence] = Field(min_length=1, max_length=20)
    summary: Text
    diagnostic_next_steps: list[Text]
    assessment: Literal["deterministic_heuristic"] = "deterministic_heuristic"
    llm_state: LLMState = LLMState.NOT_REQUESTED
    analysis: IncidentAnalysis | None = None
    failure: Literal["model_unavailable", "invalid_model_output"] | None = None
    limitations: list[Text] = Field(default_factory=lambda: ["Heuristic local correlation only"])


class RunMetrics(Contract):
    events_received: int = Field(default=0, ge=0, strict=True)
    events_retained: int = Field(default=0, ge=0, strict=True)
    noise_filtered: int = Field(default=0, ge=0, strict=True)
    duplicates_removed: int = Field(default=0, ge=0, strict=True)
    incidents_formed: int = Field(default=0, ge=0, strict=True)
    correlated_event_count: int = Field(default=0, ge=0, strict=True)
    llm_calls: int = Field(default=0, ge=0, strict=True)
    llm_calls_avoided: int = Field(default=0, ge=0, strict=True)


class RunState(Contract):
    run_id: Identifier
    started_at: datetime
    completed_at: datetime
    metrics: RunMetrics
    incident_ids: list[Identifier]
    status: Literal["completed", "collection_failed"] = "completed"


class CollectionResult(Contract):
    events: list[RawLogEvent] = Field(default_factory=list, max_length=500)
    error: Literal["unsupported_os", "command_failed", "timeout", "unavailable"] | None = None
    truncated: bool = False

    @model_validator(mode="after")
    def consistent_result(self):
        if self.error and self.events:
            raise ValueError("collection failures cannot contain operational events")
        return self


class IngestRequest(Contract):
    events: list[RawLogEvent] = Field(max_length=500)
    analyzer: Literal["none", "mock", "openrouter"] = "none"


class LifecycleRequest(Contract):
    status: Status
