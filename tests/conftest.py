"""Standard tests reject real network access and never load the user's .env."""

import pytest

from aiops.offline import network_guard


@pytest.fixture(autouse=True)
def offline(monkeypatch):
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)

    with network_guard() as attempts:
        yield
        assert not attempts, (
            "Application attempted networking even if an adapter swallowed the error"
        )
