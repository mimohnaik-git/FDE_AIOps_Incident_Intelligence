"""Explicit offline demo and optional collector commands."""

import argparse
import json
from datetime import UTC, datetime
from uuid import uuid4

from aiops.collectors import SystemLogCollector
from aiops.models import IngestRequest, RunMetrics, RunState
from aiops.pipeline import Pipeline
from aiops.sources import synthetic_events
from aiops.store import Store


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["demo", "collect"])
    parser.add_argument("--db", default="incidents.sqlite3")
    parser.add_argument("--analysis", choices=["none", "mock", "openrouter"], default="none")
    args = parser.parse_args()
    store = Store(args.db)
    try:
        events = synthetic_events()
        if args.command == "collect":
            result = SystemLogCollector().collect()
            if result.error:
                now = datetime.now(UTC)
                run = RunState(
                    run_id=uuid4().hex,
                    started_at=now,
                    completed_at=now,
                    metrics=RunMetrics(),
                    incident_ids=[],
                    status="collection_failed",
                )
                with store.db:
                    store.save_run(run)
                print(json.dumps({"error": result.error, "run": run.model_dump(mode="json")}))
                raise SystemExit(1)
            events = result.events
        run = Pipeline(store).ingest(IngestRequest(events=events, analyzer=args.analysis))
        print(
            json.dumps(
                {
                    "run": run.model_dump(mode="json"),
                    "incidents": [item.model_dump(mode="json") for item in store.incidents()],
                },
                indent=2,
            )
        )
    finally:
        store.close()


if __name__ == "__main__":
    main()
