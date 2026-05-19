from __future__ import annotations

import argparse
import sqlite3
import uuid
from pathlib import Path

from rekos.cli import build_parser, main
from rekos.usernames import username_variants


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
    assert "add-entity" in subcommands
    assert "relate-entities" in subcommands
    assert "list-entities" in subcommands
    assert "graph-summary" in subcommands
    assert "username-variants" in subcommands
    assert "add-username-target" in subcommands


def test_username_variant_generation_and_deduplication() -> None:
    variants = username_variants("Alice.Smith_test")

    assert [variant.value for variant in variants] == [
        "Alice.Smith_test",
        "alice.smith_test",
        "AliceSmith_test",
        "Alice.Smithtest",
        "Alice_Smith_test",
        "Alice.Smith.test",
        "AliceSmithtest",
    ]
    assert [variant.confidence for variant in variants] == [
        None,
        "high",
        "low",
        "low",
        "medium",
        "medium",
        "low",
    ]
    assert [variant.value for variant in username_variants("alice")] == ["alice"]


def test_username_variants_command_outputs_deduplicated_variants(capsys) -> None:
    assert main(["username-variants", "Alice.Smith_test"]) == 0

    output = capsys.readouterr().out
    assert "Alice.Smith_test" in output
    assert "alice.smith_test (high)" in output
    assert "Alice_Smith_test (medium)" in output
    assert "AliceSmithtest (low)" in output


def test_entity_creation_persists_uuid(tmp_path: Path, monkeypatch, capsys) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))

    assert main(["new-case", "case-graph"]) == 0
    assert main(
        [
            "add-entity",
            "case-graph",
            "--type",
            "username",
            "--value",
            "alice",
            "--note",
            "public profile",
        ]
    ) == 0

    output = capsys.readouterr().out
    assert "Added entity" in output

    db_path = tmp_path / "rekos_cases" / "case-graph" / "rekos.db"
    with sqlite3.connect(db_path) as connection:
        row = connection.execute(
            "SELECT entity_id, entity_type, value, note FROM entities"
        ).fetchone()
        event_type = connection.execute(
            "SELECT event_type FROM timeline_events ORDER BY id DESC LIMIT 1"
        ).fetchone()[0]

    uuid.UUID(row[0])
    assert row[1:] == ("username", "alice", "public profile")
    assert event_type == "entity.created"


def test_add_username_target_creates_variant_graph(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))

    assert main(["new-case", "case-user-target"]) == 0
    assert main(["add-username-target", "case-user-target", "Alice.Smith_test"]) == 0

    output = capsys.readouterr().out
    assert "Added username target" in output
    assert "Variants: 6" in output

    db_path = tmp_path / "rekos_cases" / "case-user-target" / "rekos.db"
    with sqlite3.connect(db_path) as connection:
        entities = connection.execute(
            "SELECT entity_id, entity_type, value, note FROM entities ORDER BY id"
        ).fetchall()
        relationships = connection.execute(
            """
            SELECT relationship_type, confidence, note
            FROM relationships
            ORDER BY id
            """
        ).fetchall()
        event_types = [
            row[0]
            for row in connection.execute(
                "SELECT event_type FROM timeline_events ORDER BY id"
            ).fetchall()
        ]

    assert [row[2] for row in entities] == [
        "Alice.Smith_test",
        "alice.smith_test",
        "AliceSmith_test",
        "Alice.Smithtest",
        "Alice_Smith_test",
        "Alice.Smith.test",
        "AliceSmithtest",
    ]
    assert all(row[1] == "username" for row in entities)
    assert entities[0][3] == "original username target"
    assert all(row[0] == "possible_match" for row in relationships)
    assert [row[1] for row in relationships] == [
        "high",
        "low",
        "low",
        "medium",
        "medium",
        "low",
    ]
    assert all(row[2] == "username variant correlation" for row in relationships)
    assert event_types.count("entity.created") == 7
    assert event_types.count("relationship.created") == 6


def test_relationship_creation_persists_with_confidence(
    tmp_path: Path, monkeypatch
) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))

    assert main(["new-case", "case-rel"]) == 0
    assert main(["add-entity", "case-rel", "--type", "username", "--value", "alice"]) == 0
    assert main(["add-entity", "case-rel", "--type", "domain", "--value", "example.com"]) == 0

    db_path = tmp_path / "rekos_cases" / "case-rel" / "rekos.db"
    with sqlite3.connect(db_path) as connection:
        entity_ids = [
            row[0]
            for row in connection.execute(
                "SELECT entity_id FROM entities ORDER BY id"
            ).fetchall()
        ]

    assert main(
        [
            "relate-entities",
            "case-rel",
            "--from",
            entity_ids[0],
            "--to",
            entity_ids[1],
            "--type",
            "same_target",
            "--confidence",
            "high",
            "--note",
            "profile links domain",
        ]
    ) == 0

    with sqlite3.connect(db_path) as connection:
        row = connection.execute(
            """
            SELECT relationship_id, source_entity_id, target_entity_id,
                   relationship_type, confidence, note
            FROM relationships
            """
        ).fetchone()
        event_type = connection.execute(
            "SELECT event_type FROM timeline_events ORDER BY id DESC LIMIT 1"
        ).fetchone()[0]

    uuid.UUID(row[0])
    assert row[1:] == (
        entity_ids[0],
        entity_ids[1],
        "same_target",
        "high",
        "profile links domain",
    )
    assert event_type == "relationship.created"


def test_relationship_confidence_validation(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))

    assert main(["new-case", "case-confidence"]) == 0
    assert main(["add-entity", "case-confidence", "--type", "username", "--value", "alice"]) == 0
    assert main(["add-entity", "case-confidence", "--type", "domain", "--value", "example.com"]) == 0

    db_path = tmp_path / "rekos_cases" / "case-confidence" / "rekos.db"
    with sqlite3.connect(db_path) as connection:
        entity_ids = [
            row[0]
            for row in connection.execute(
                "SELECT entity_id FROM entities ORDER BY id"
            ).fetchall()
        ]

    assert main(
        [
            "relate-entities",
            "case-confidence",
            "--from",
            entity_ids[0],
            "--to",
            entity_ids[1],
            "--type",
            "related_to",
            "--confidence",
            "certain",
        ]
    ) == 1

    captured = capsys.readouterr()
    assert "Unsupported confidence" in captured.err


def test_graph_summary_counts_and_most_connected(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))

    assert main(["new-case", "case-summary"]) == 0
    assert main(["add-entity", "case-summary", "--type", "username", "--value", "alice"]) == 0
    assert main(["add-entity", "case-summary", "--type", "domain", "--value", "example.com"]) == 0
    assert main(["add-entity", "case-summary", "--type", "url", "--value", "https://example.com/a"]) == 0

    db_path = tmp_path / "rekos_cases" / "case-summary" / "rekos.db"
    with sqlite3.connect(db_path) as connection:
        entity_ids = [
            row[0]
            for row in connection.execute(
                "SELECT entity_id FROM entities ORDER BY id"
            ).fetchall()
        ]

    assert main(
        [
            "relate-entities",
            "case-summary",
            "--from",
            entity_ids[0],
            "--to",
            entity_ids[1],
            "--type",
            "same_target",
            "--confidence",
            "medium",
        ]
    ) == 0
    assert main(
        [
            "relate-entities",
            "case-summary",
            "--from",
            entity_ids[1],
            "--to",
            entity_ids[2],
            "--type",
            "referenced_by",
            "--confidence",
            "low",
        ]
    ) == 0
    capsys.readouterr()

    assert main(["graph-summary", "case-summary"]) == 0

    output = capsys.readouterr().out
    assert "Total entities: 3" in output
    assert "Total relationships: 2" in output
    assert "- domain: 1" in output
    assert "- username: 1" in output
    assert "example.com (2)" in output


def test_report_renders_graph_sections(tmp_path: Path, monkeypatch, capsys) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))

    assert main(["new-case", "case-report-graph"]) == 0
    assert main(["add-entity", "case-report-graph", "--type", "email", "--value", "a@example.com"]) == 0
    assert main(["add-entity", "case-report-graph", "--type", "domain", "--value", "example.com"]) == 0

    db_path = tmp_path / "rekos_cases" / "case-report-graph" / "rekos.db"
    with sqlite3.connect(db_path) as connection:
        entity_ids = [
            row[0]
            for row in connection.execute(
                "SELECT entity_id FROM entities ORDER BY id"
            ).fetchall()
        ]

    assert main(
        [
            "relate-entities",
            "case-report-graph",
            "--from",
            entity_ids[0],
            "--to",
            entity_ids[1],
            "--type",
            "possible_match",
            "--confidence",
            "medium",
        ]
    ) == 0
    capsys.readouterr()

    assert main(["report", "case-report-graph"]) == 0

    output = capsys.readouterr().out
    assert "## Entities" in output
    assert "`email`: a@example.com" in output
    assert "## Relationships" in output
    assert "`possible_match` (medium)" in output
    assert "## Graph Summary" in output
    assert "Total entities: 2" in output


def test_report_renders_username_variants_and_correlations(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))

    assert main(["new-case", "case-variant-report"]) == 0
    assert main(["add-username-target", "case-variant-report", "Alice.Smith_test"]) == 0
    capsys.readouterr()

    assert main(["report", "case-variant-report"]) == 0

    output = capsys.readouterr().out
    assert "Alice.Smith_test" in output
    assert "alice.smith_test" in output
    assert "`possible_match` (high)" in output
    assert "`possible_match` (medium)" in output
    assert "`possible_match` (low)" in output
    assert "username variant correlation" in output


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
