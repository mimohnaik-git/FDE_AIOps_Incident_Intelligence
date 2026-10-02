"""Opt-in, bounded adapters for recent operating-system journal records."""

import asyncio
import platform
from datetime import UTC, datetime

from aiops.models import CollectionResult, RawLogEvent


class SystemLogCollector:
    """Read a short, fixed-size window without invoking a shell or retaining raw output."""

    _MAX_BYTES = 128_000
    _MAX_RECORDS = 500
    _DEADLINE_SECONDS = 10

    def __init__(self, minutes: int = 1):
        if not 1 <= minutes <= 60:
            raise ValueError("minutes must be between 1 and 60")
        self.minutes = minutes

    def _command(self, system: str) -> list[str] | None:
        if system == "Linux":
            return [
                "journalctl",
                "--since",
                f"{self.minutes} minutes ago",
                "--lines=500",
                "--no-pager",
                "--output=short-iso",
            ]
        if system == "Darwin":
            return ["log", "show", "--last", f"{self.minutes}m", "--style", "compact"]
        if system == "Windows":
            elapsed_ms = self.minutes * 60_000
            query = f"*[System[TimeCreated[timediff(@SystemTime) <= {elapsed_ms}]]]"
            return [
                "wevtutil",
                "qe",
                "System",
                f"/q:{query}",
                "/c:500",
                "/rd:true",
                "/f:text",
            ]
        return None

    def collect(self) -> CollectionResult:
        command = self._command(platform.system())
        if command is None:
            return CollectionResult(error="unsupported_os")
        return self._read(command)

    async def _launch(self, command: list[str]):
        return await asyncio.create_subprocess_exec(
            *command,
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
            limit=8192,
        )

    async def _read_async(self, command: list[str]) -> CollectionResult:
        try:
            process = await self._launch(command)
        except (OSError, ValueError):
            return CollectionResult(error="unavailable")

        captured = bytearray()
        state = {"truncated": False}

        async def drain_stream() -> None:
            while chunk := await process.stdout.read(4096):
                capacity = self._MAX_BYTES - len(captured)
                captured.extend(chunk[:capacity])
                if len(chunk) > capacity:
                    state["truncated"] = True
                    process.kill()
                    while await process.stdout.read(4096):
                        pass
                    return

        reader = asyncio.create_task(drain_stream())
        try:
            await asyncio.wait_for(process.wait(), timeout=self._DEADLINE_SECONDS)
            await reader
        except TimeoutError:
            process.kill()
            await process.wait()
            reader.cancel()
            await asyncio.gather(reader, return_exceptions=True)
            return CollectionResult(error="timeout")
        except (OSError, ValueError):
            process.kill()
            await process.wait()
            reader.cancel()
            await asyncio.gather(reader, return_exceptions=True)
            return CollectionResult(error="unavailable")

        if process.returncode and not state["truncated"]:
            return CollectionResult(error="command_failed")

        lines = [
            line[:4096] for line in captured.decode("utf-8", "replace").splitlines() if line.strip()
        ]
        sampled_at = datetime.now(UTC)
        events = [
            RawLogEvent(
                timestamp=sampled_at,
                source="system",
                component="system",
                message=line,
            )
            for line in lines[: self._MAX_RECORDS]
        ]
        return CollectionResult(
            events=events,
            truncated=state["truncated"] or len(lines) > self._MAX_RECORDS,
        )

    def _read(self, command: list[str]) -> CollectionResult:
        return asyncio.run(self._read_async(command))
