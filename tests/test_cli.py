from __future__ import annotations

import argparse
import sqlite3
from pathlib import Path

from rekos.cli import build_parser, main


def test_case_lifecycle_generates_markdown_report(tmp_path: Path, monkeypatch, capsys) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    artifact = tmp_path / "artifact.txt"
    artifact.write_text("forensic sample\n", encoding="utf-8")

    assert main(["new-case", "case-001"]) == 0
    assert main(["add-target", "case-001", "--type", "username", "--value", "alice"]) == 0
    assert main(["hash-file", "case-001", str(artifact)]) == 0
    assert main(["add-note", "case-001", "Initial triage note"]) == 0
    assert main(["report", "case-001", "--format", "md"]) == 0

    output = capsys.readouterr().out
    assert "# REKOS Case Report: case-001" in output
    assert "`username`: alice" in output
    assert "Initial triage note" in output
    assert "SHA-256" in output

    db_path = tmp_path / "rekos_cases" / "case-001" / "rekos.db"
    assert db_path.exists()
    with sqlite3.connect(db_path) as connection:
        target_count = connection.execute("SELECT COUNT(*) FROM targets").fetchone()[0]
        file_count = connection.execute("SELECT COUNT(*) FROM file_hashes").fetchone()[0]
        note_count = connection.execute("SELECT COUNT(*) FROM notes").fetchone()[0]

    assert target_count == 1
    assert file_count == 1
    assert note_count == 1


def test_passive_osint_commands_are_registered() -> None:
    parser = build_parser()
    subparser_action = next(
        action
        for action in parser._actions
        if isinstance(action, argparse._SubParsersAction)
    )
    subcommands = subparser_action.choices

    assert "metadata" in subcommands
    assert "username-scan" in subcommands


def test_metadata_returns_clear_error_when_tools_are_missing(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setattr("rekos.osint.shutil.which", lambda _tool: None)
    artifact = tmp_path / "artifact with spaces.txt"
    artifact.write_text("sample\n", encoding="utf-8")

    assert main(["new-case", "case-meta"]) == 0
    assert main(["metadata", "case-meta", str(artifact)]) == 1

    captured = capsys.readouterr()
    assert "Missing metadata tool" in captured.err

    db_path = tmp_path / "rekos_cases" / "case-meta" / "rekos.db"
    with sqlite3.connect(db_path) as connection:
        metadata_count = connection.execute(
            "SELECT COUNT(*) FROM metadata_findings"
        ).fetchone()[0]
    assert metadata_count == 0


def test_username_scan_returns_clear_error_when_sherlock_is_missing(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setattr("rekos.osint.shutil.which", lambda _tool: None)

    assert main(["new-case", "case-user"]) == 0
    assert main(["username-scan", "case-user", "alice.test+case"]) == 1

    captured = capsys.readouterr()
    assert "Missing username scan tool" in captured.err

    db_path = tmp_path / "rekos_cases" / "case-user" / "rekos.db"
    with sqlite3.connect(db_path) as connection:
        scan_count = connection.execute("SELECT COUNT(*) FROM username_scans").fetchone()[0]
    assert scan_count == 0


def test_case_name_rejects_path_traversal(tmp_path: Path, monkeypatch, capsys) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))

    assert main(["new-case", "../escape"]) == 1

    captured = capsys.readouterr()
    assert "path separators" in captured.err
    assert not (tmp_path / "escape").exists()


def test_only_username_targets_are_supported(tmp_path: Path, monkeypatch, capsys) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))

    assert main(["new-case", "case-002"]) == 0
    assert main(["add-target", "case-002", "--type", "email", "--value", "a@example.com"]) == 1

    captured = capsys.readouterr()
    assert "Unsupported target type" in captured.err


def test_missing_case_returns_error(tmp_path: Path, monkeypatch, capsys) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))

    assert main(["add-note", "missing", "note"]) == 1

    captured = capsys.readouterr()
    assert "Case not found" in captured.err
