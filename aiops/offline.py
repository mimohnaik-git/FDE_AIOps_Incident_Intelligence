"""Verification network guard; allow only Python's internal Windows socketpair setup."""

import inspect
import socket
from contextlib import contextmanager
from unittest.mock import patch


@contextmanager
def network_guard():
    original = socket.socket.connect
    attempts = []

    def guarded(sock, address):
        caller = inspect.currentframe().f_back
        # Windows asyncio implements its wakeup pipe using a local socketpair.
        if (
            caller.f_code.co_name == "_fallback_socketpair"
            and caller.f_code.co_filename == socket.__file__
            and address[0] in {"127.0.0.1", "::1"}
        ):
            return original(sock, address)
        attempts.append("blocked_connection")
        raise AssertionError("Unexpected application network access")

    def blocked(*args, **kwargs):
        attempts.append("blocked_connection")
        raise AssertionError("Unexpected application network access")

    with patch("socket.socket.connect", guarded), patch("socket.socket.connect_ex", blocked):
        yield attempts
