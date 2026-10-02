"""Deterministic synthetic fixtures for offline incident-pipeline demonstrations."""

from datetime import UTC, datetime, timedelta

from aiops.models import RawLogEvent


def synthetic_events() -> list[RawLogEvent]:
    start = datetime(2026, 1, 1, tzinfo=UTC)
    samples = [
        ("scheduler", "Lease extension acknowledged for shard blue"),
        ("database", "Commit quorum lost; writes are being rejected"),
        ("database", "Commit quorum lost; writes are being rejected"),
        ("database", "Replica apply lag exceeded 90 seconds"),
        ("storage", "Ledger verification found a broken hash chain"),
        ("application", "Canary rollout reached its observation window"),
    ]
    return [
        RawLogEvent(timestamp=start + timedelta(seconds=i), component=component, message=message)
        for i, (component, message) in enumerate(samples)
    ]
