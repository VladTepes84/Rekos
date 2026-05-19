from __future__ import annotations

import argparse
import json
import sqlite3
import uuid
import zipfile
from pathlib import Path
from types import SimpleNamespace

from rekos.cli import build_parser, main
from rekos.osint import _write_export


def test_case_lifecycle_generates_markdown_report(tmp_path: Path, monkeypatch, capsys) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    artifact = tmp_path / "artifact.txt"
    artifact.write_text("public sample\n", encoding="utf-8")

    assert main(["new-case", "case-001"]) == 0
    assert main(["add-target", "case-001", "--type", "username", "--value", "alice"]) == 0
    assert main(["hash-file", "case-001", str(artifact)]) == 0
    assert main(["add-note", "case-001", "Initial triage note"]) == 0
    assert main(["report", "case-001", "--format", "md"]) == 0

    output = capsys.readouterr().out
    assert "# REKOS OSINT Workspace Report: case-001" in output
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
    assert "validate-case" in subcommands
    assert "export-case" in subcommands
    assert "add-ioc" in subcommands
    assert "list-iocs" in subcommands
    assert "enrich-ioc" in subcommands


def test_add_and_list_valid_iocs(tmp_path: Path, monkeypatch, capsys) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))

    assert main(["new-case", "case-iocs"]) == 0
    assert main(["add-ioc", "case-iocs", "--type", "ip", "--value", "8.8.8.8", "--note", "resolver"]) == 0
    assert main(["add-ioc", "case-iocs", "--type", "domain", "--value", "Bücher.example", "--note", "idna"]) == 0
    assert main([
        "add-ioc",
        "case-iocs",
        "--type",
        "url",
        "--value",
        "https://example.com/path?x=1",
        "--note",
        "landing",
    ]) == 0
    assert main([
        "add-ioc",
        "case-iocs",
        "--type",
        "hash",
        "--value",
        "A" * 64,
        "--note",
        "payload",
    ]) == 0
    capsys.readouterr()

    assert main(["list-iocs", "case-iocs"]) == 0

    output = capsys.readouterr().out
    assert "ip: 8.8.8.8 - resolver" in output
    assert "domain: xn--bcher-kva.example - idna" in output
    assert "a" * 64 in output

    db_path = tmp_path / "rekos_cases" / "case-iocs" / "rekos.db"
    with sqlite3.connect(db_path) as connection:
        rows = connection.execute("SELECT type, value, note FROM iocs ORDER BY id").fetchall()
        event_types = [
            row[0]
            for row in connection.execute(
                "SELECT event_type FROM timeline_events ORDER BY id"
            ).fetchall()
        ]

    assert rows == [
        ("ip", "8.8.8.8", "resolver"),
        ("domain", "xn--bcher-kva.example", "idna"),
        ("url", "https://example.com/path?x=1", "landing"),
        ("hash", "a" * 64, "payload"),
    ]
    assert event_types.count("ioc.added") == 4
    assert "ioc.listed" in event_types


def test_invalid_iocs_are_rejected(tmp_path: Path, monkeypatch, capsys) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))

    assert main(["new-case", "case-invalid-iocs"]) == 0
    assert main(["add-ioc", "case-invalid-iocs", "--type", "ip", "--value", "999.1.1.1", "--note", "bad"]) == 1
    assert main(["add-ioc", "case-invalid-iocs", "--type", "domain", "--value", "bad_domain", "--note", "bad"]) == 1
    assert main(["add-ioc", "case-invalid-iocs", "--type", "url", "--value", "ftp://example.com", "--note", "bad"]) == 1
    assert main(["add-ioc", "case-invalid-iocs", "--type", "hash", "--value", "not-a-hash", "--note", "bad"]) == 1

    captured = capsys.readouterr()
    assert "Error:" in captured.err

    db_path = tmp_path / "rekos_cases" / "case-invalid-iocs" / "rekos.db"
    with sqlite3.connect(db_path) as connection:
        ioc_count = connection.execute("SELECT COUNT(*) FROM iocs").fetchone()[0]
    assert ioc_count == 0


def test_enrich_ioc_is_local_and_persists_result(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))

    assert main(["new-case", "case-enrich"]) == 0
    assert main(["enrich-ioc", "case-enrich", "--type", "ip", "--value", "127.0.0.1"]) == 0
    assert main(["enrich-ioc", "case-enrich", "--type", "url", "--value", "https://example.com/a?b=1"]) == 0

    output = capsys.readouterr().out
    assert '"loopback": true' in output
    assert '"has_query": true' in output

    db_path = tmp_path / "rekos_cases" / "case-enrich" / "rekos.db"
    with sqlite3.connect(db_path) as connection:
        rows = connection.execute(
            "SELECT type, value, enrichment FROM ioc_enrichments ORDER BY id"
        ).fetchall()
        event_types = [
            row[0]
            for row in connection.execute(
                "SELECT event_type FROM timeline_events ORDER BY id"
            ).fetchall()
        ]

    assert rows[0][0:2] == ("ip", "127.0.0.1")
    assert '"version": 4' in rows[0][2]
    assert rows[1][0:2] == ("url", "https://example.com/a?b=1")
    assert '"host": "example.com"' in rows[1][2]
    assert event_types.count("ioc.enriched") == 2


def test_report_renders_ioc_section(tmp_path: Path, monkeypatch, capsys) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))

    assert main(["new-case", "case-ioc-report"]) == 0
    assert main([
        "add-ioc",
        "case-ioc-report",
        "--type",
        "domain",
        "--value",
        "example.com",
        "--note",
        "reported domain",
    ]) == 0
    assert main(["enrich-ioc", "case-ioc-report", "--type", "hash", "--value", "b" * 32]) == 0
    capsys.readouterr()

    assert main(["report", "case-ioc-report"]) == 0

    output = capsys.readouterr().out
    assert "## IOCs" in output
    assert "`domain`: example.com" in output
    assert "reported domain" in output
    assert "## IOC Enrichments" in output
    assert '"algorithm": "MD5"' in output


def test_validate_case_reports_healthy_case(tmp_path: Path, monkeypatch, capsys) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    artifact = tmp_path / "healthy.txt"
    artifact.write_text("healthy sample\n", encoding="utf-8")

    assert main(["new-case", "case-healthy"]) == 0
    assert main(["hash-file", "case-healthy", str(artifact)]) == 0
    capsys.readouterr()

    assert main(["validate-case", "case-healthy"]) == 0

    output = capsys.readouterr().out
    assert "Case validation passed" in output

    db_path = tmp_path / "rekos_cases" / "case-healthy" / "rekos.db"
    with sqlite3.connect(db_path) as connection:
        row = connection.execute(
            "SELECT status, warnings FROM validation_summaries"
        ).fetchone()
    assert row == ("ok", "")


def test_validate_case_detects_missing_db(tmp_path: Path, monkeypatch, capsys) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    case_folder = tmp_path / "rekos_cases" / "case-no-db"
    case_folder.mkdir(parents=True)

    assert main(["validate-case", "case-no-db"]) == 1

    output = capsys.readouterr().out
    assert "SQLite DB missing" in output


def test_validate_case_detects_missing_evidence_file(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    artifact = tmp_path / "missing-evidence.txt"
    artifact.write_text("evidence sample\n", encoding="utf-8")

    assert main(["new-case", "case-missing-evidence"]) == 0
    assert main(["hash-file", "case-missing-evidence", str(artifact)]) == 0
    artifact.unlink()
    capsys.readouterr()

    assert main(["validate-case", "case-missing-evidence"]) == 1

    output = capsys.readouterr().out
    assert "Evidence file missing" in output


def test_validate_case_detects_hash_mismatch(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    artifact = tmp_path / "hash-mismatch.txt"
    artifact.write_text("original\n", encoding="utf-8")

    assert main(["new-case", "case-hash-mismatch"]) == 0
    assert main(["hash-file", "case-hash-mismatch", str(artifact)]) == 0
    artifact.write_text("modified\n", encoding="utf-8")
    capsys.readouterr()

    assert main(["validate-case", "case-hash-mismatch"]) == 1

    output = capsys.readouterr().out
    assert "Evidence SHA256 mismatch" in output


def test_export_case_zip_contains_manifest_files(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    artifact = tmp_path / "outside-evidence.txt"
    artifact.write_text("outside evidence\n", encoding="utf-8")
    output_zip = tmp_path / "case-export.zip"

    assert main(["new-case", "case-export"]) == 0
    assert main(["hash-file", "case-export", str(artifact)]) == 0
    assert main(["add-note", "case-export", "Export note"]) == 0
    capsys.readouterr()

    assert main(["export-case", "case-export", "--output", str(output_zip)]) == 0

    assert output_zip.exists()
    assert not list(tmp_path.glob(".case-export.zip.*.tmp"))
    with zipfile.ZipFile(output_zip) as archive:
        names = set(archive.namelist())
        assert "rekos.db" in names
        assert "reports/case-report.md" in names
        assert "manifest.json" in names
        assert "manifest.sha256" in names
        assert "outside-evidence.txt" not in names
        manifest = json.loads(archive.read("manifest.json"))
        manifest_sha = archive.read("manifest.sha256").decode("utf-8")

    manifest_paths = {entry["path"] for entry in manifest["files"]}
    assert {"rekos.db", "reports/case-report.md"} <= manifest_paths
    assert all(entry["sha256"] for entry in manifest["files"])
    assert "manifest.json" in manifest_sha


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
