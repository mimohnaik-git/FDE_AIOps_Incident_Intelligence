"""Impact-first local classification rules for a small service platform."""

import re

from aiops.models import Department, NormalizedEvent, RoutingDecision, Severity

# Priorities describe observed service impact, not the technology named in a message:
# P0 is a broad hard outage or a credible integrity breach; P1 is a major service
# objective breach or loss of a recovery path; P2 is bounded user impact; P3 is an
# approaching limit; P4 is retained context; P5 is routine telemetry discarded by
# the ingestion pipeline. Keep phrases concrete and avoid treating predictions as facts.
RULES = {
    Severity.P0: (
        "all api replicas refused readiness probes",
        "commit quorum lost",
        "ledger verification found a broken hash chain",
        "signing key set is unavailable",
        "tenant routing table is empty",
        "object catalog contains two active writers",
    ),
    Severity.P1: (
        "replica apply lag exceeded 90 seconds",
        "consumer offset stalled beyond recovery budget",
        "partition backlog crossed 120k records",
        "name service misses exceeded 35 percent",
        "regional checkout requests are being rejected",
        "deployment rollback could not restore the previous release",
    ),
    Severity.P2: (
        "consumer group exceeded its delivery deadline",
        "checkout p95 crossed 1.8 seconds",
        "token refresh failed for one identity shard",
        "scheduled export missed its delivery window",
        "search index is serving an older generation",
    ),
    Severity.P3: (
        "queue depth reached 72 percent of its guardrail",
        "certificate renewal enters its 14 day window",
        "replica lag reached 12 seconds",
        "object growth forecast crossed the weekly reserve",
    ),
    Severity.P5: (
        "lease extension acknowledged",
        "index compaction pass finished",
        "canary sample recorded",
        "cache namespace warmed",
        "probe sample acknowledged",
    ),
}


def assess(event: NormalizedEvent) -> tuple[Severity, str, RoutingDecision]:
    text = event.message.casefold()
    severity, reason = Severity.P4, "No impact threshold matched; retain for review"
    for candidate, phrases in RULES.items():
        phrase = next((item for item in phrases if item in text), None)
        if phrase:
            severity, reason = candidate, f"Impact rule matched: {phrase}"
            break

    # The rate rule uses a measured percentage and a documented P1 boundary.
    rejection_rate = re.search(r"rejected requests\s+(\d+(?:\.\d+)?)%", text)
    if rejection_rate and float(rejection_rate.group(1)) >= 40:
        severity, reason = Severity.P1, "Impact rule matched: rejected request rate >= 40%"

    ownership = {
        "network": Department.NETWORK,
        "storage": Department.INFRASTRUCTURE,
        "scheduler": Department.SYSTEM_ADMIN,
        "system": Department.SYSTEM_ADMIN,
        "database": Department.DATABASE,
        "identity": Department.SECURITY,
        "security": Department.SECURITY,
    }
    department = ownership.get(event.component, Department.APPLICATION)
    if "credential spray" in text or "signing key" in text:
        department = Department.SECURITY

    return (
        severity,
        reason,
        RoutingDecision(
            departments=[department],
            reason=f"Owning component {event.component}; {reason}",
        ),
    )
