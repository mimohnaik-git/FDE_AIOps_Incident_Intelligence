from pathlib import Path
from types import SimpleNamespace

from scripts.secret_check import scan


def test_scanner_detects_tokens_without_exposing_values(tmp_path, monkeypatch):
    monkeypatch.setattr(
        "scripts.secret_check.__file__", str(tmp_path / "scripts" / "secret_check.py")
    )
    root = tmp_path
    path = tmp_path / "credential-fixture.txt"
    token = "ghp_" + "a" * 36
    path.write_text("credential: " + token, encoding="utf-8")
    relative = path.relative_to(root).as_posix()
    monkeypatch.setattr(
        "scripts.secret_check.subprocess.run",
        lambda *a, **kw: SimpleNamespace(stdout=relative.encode() + b"\0"),
    )
    findings = scan()
    assert len(findings) == 1 and relative in findings[0]
    assert token not in findings[0]


def test_scanner_never_reads_tracked_env(monkeypatch):
    monkeypatch.setattr(
        "scripts.secret_check.subprocess.run", lambda *a, **kw: SimpleNamespace(stdout=b".env\0")
    )
    monkeypatch.setattr(
        Path,
        "read_bytes",
        lambda *a: (_ for _ in ()).throw(AssertionError("Must not read the real environment file")),
    )
    assert scan() == [".env: tracked environment file"]
