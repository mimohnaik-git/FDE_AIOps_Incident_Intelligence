"""Run synthetic ingestion, persistence, replay, and API review with networking blocked."""

import json
import tempfile
from pathlib import Path

from fastapi.testclient import TestClient

from aiops.api import create_app
from aiops.offline import network_guard


def main():
    with tempfile.TemporaryDirectory() as directory, network_guard() as attempts:
        path = str(Path(directory) / "e2e.sqlite3")
        with TestClient(create_app(path)) as client:
            assert client.get("/health").status_code == 200
            first = client.post("/demo").json()
            incidents = client.get("/incidents").json()
            assert len(incidents) == 3
            assert sorted((i["component"], i["severity"], i["event_count"]) for i in incidents) == [
                ("application", "P4", 1),
                ("database", "P0", 3),
                ("storage", "P0", 1),
            ]
            replay = client.post("/demo").json()
            assert first["metrics"]["llm_calls"] == replay["metrics"]["llm_calls"] == 0
            assert replay["metrics"]["incidents_formed"] == 0
        with TestClient(create_app(path)) as client:
            assert len(client.get("/incidents").json()) == 3
        assert not attempts
        print(
            json.dumps(
                {
                    "result": "PASS",
                    "incidents": 3,
                    "first_run": first["metrics"],
                    "replay": replay["metrics"],
                    "network_calls": 0,
                },
                indent=2,
            )
        )


if __name__ == "__main__":
    main()
