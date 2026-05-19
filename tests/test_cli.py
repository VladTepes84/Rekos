from __future__ import annotations

import argparse
import sqlite3
import uuid
from pathlib import Path
from types import SimpleNamespace

from rekos.cli import build_parser, main
from rekos.osint import _write_export


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


def test_case_uuid_is_stable_and_actions_create_timeline_events(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    artifact = tmp_path / "timeline.txt"
    artifact.write_text("timeline sample\n", encoding="utf-8")

    assert main(["new-case", "case-timeline"]) == 0
    db_path = tmp_path / "rekos_cases" / "case-timeline" / "rekos.db"
    with sqlite3.connect(db_path) as connection:
        first_uuid = connection.execute("SELECT uuid FROM cases").fetchone()[0]
    uuid.UUID(first_uuid)

    assert main(["add-target", "case-timeline", "--type", "username", "--value", "alice"]) == 0
    assert main(["hash-file", "case-timeline", str(artifact)]) == 0
    assert main(["add-note", "case-timeline", "Timeline note"]) == 0
    capsys.readouterr()
    assert main(["report", "case-timeline"]) == 0

    with sqlite3.connect(db_path) as connection:
        second_uuid = connection.execute("SELECT uuid FROM cases").fetchone()[0]
        event_types = [
            row[0]
            for row in connection.execute(
                "SELECT event_type FROM timeline_events ORDER BY id"
            ).fetchall()
        ]

    assert second_uuid == first_uuid
    assert event_types == [
        "case.created",
        "target.added",
        "file.hashed",
        "note.added",
        "report.rendered",
    ]


def test_hash_file_creates_evidence_record(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    artifact = tmp_path / "evidence.bin"
    artifact.write_text("evidence sample\n", encoding="utf-8")

    assert main(["new-case", "case-evidence"]) == 0
    assert main(["hash-file", "case-evidence", str(artifact)]) == 0

    db_path = tmp_path / "rekos_cases" / "case-evidence" / "rekos.db"
    with sqlite3.connect(db_path) as connection:
        row = connection.execute(
            """
            SELECT evidence_id, type, path, sha256, created_at, source_url, note
            FROM evidence
            """
        ).fetchone()
        file_hash = connection.execute("SELECT sha256 FROM file_hashes").fetchone()[0]

    assert row is not None
    uuid.UUID(row[0])
    assert row[1] == "file"
    assert row[2] == str(artifact.resolve())
    assert row[3] == file_hash
    assert row[4]
    assert row[5] is None
    assert "Hashed file" in row[6]


def test_export_writes_use_temp_file_then_atomic_rename(
    tmp_path: Path, monkeypatch
) -> None:
    exports = tmp_path / "exports"
    exports.mkdir()
    replace_calls: list[tuple[str, str]] = []
    original_replace = Path.replace

    def recording_replace(self: Path, target: Path) -> Path:
        replace_calls.append((self.name, Path(target).name))
        return original_replace(self, target)

    monkeypatch.setattr(Path, "replace", recording_replace)

    export_path = _write_export(exports, "scan", "raw output\n")

    assert export_path == exports / "scan.txt"
    assert export_path.read_text(encoding="utf-8") == "raw output\n"
    assert replace_calls
    temp_name, final_name = replace_calls[0]
    assert temp_name.startswith(".scan.txt.")
    assert temp_name.endswith(".tmp")
    assert final_name == "scan.txt"
    assert list(exports.glob("*.tmp")) == []


def test_report_redacts_absolute_paths_by_default(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    artifact = tmp_path / "redacted-artifact.txt"
    artifact.write_text("redacted sample\n", encoding="utf-8")

    assert main(["new-case", "case-redaction"]) == 0
    assert main(["hash-file", "case-redaction", str(artifact)]) == 0
    capsys.readouterr()

    assert main(["report", "case-redaction"]) == 0

    output = capsys.readouterr().out
    assert str(tmp_path) not in output
    assert "`redacted-artifact.txt`" in output


def test_metadata_success_persists_export_evidence_and_relative_report_path(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    artifact = tmp_path / "photo.jpg"
    artifact.write_text("image bytes\n", encoding="utf-8")

    monkeypatch.setattr("rekos.osint.shutil.which", lambda tool: f"/usr/bin/{tool}")

    def fake_run(cmd, check, capture_output, text, timeout):
        assert check is False
        assert capture_output is True
        assert text is True
        assert timeout == 120
        assert cmd[0] in {"/usr/bin/exiftool", "/usr/bin/mediainfo"}
        assert cmd[1] == str(artifact.resolve())
        return SimpleNamespace(returncode=0, stdout=f"{Path(cmd[0]).name} output\n", stderr="")

    monkeypatch.setattr("rekos.osint.subprocess.run", fake_run)

    assert main(["new-case", "case-metadata-success"]) == 0
    assert main(["metadata", "case-metadata-success", str(artifact)]) == 0
    capsys.readouterr()
    assert main(["report", "case-metadata-success"]) == 0

    db_path = tmp_path / "rekos_cases" / "case-metadata-success" / "rekos.db"
    with sqlite3.connect(db_path) as connection:
        metadata_row = connection.execute(
            "SELECT export_path FROM metadata_findings"
        ).fetchone()
        evidence_row = connection.execute(
            "SELECT type, path FROM evidence WHERE type = 'metadata_export'"
        ).fetchone()

    assert metadata_row is not None
    export_path = Path(metadata_row[0])
    assert export_path.exists()
    assert export_path.parent.name == "exports"
    assert evidence_row == ("metadata_export", str(export_path))

    output = capsys.readouterr().out
    assert str(tmp_path) not in output
    assert "`exports/metadata-photo.jpg.txt`" in output


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
