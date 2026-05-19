from __future__ import annotations

import argparse
import json
import sqlite3
import uuid
from pathlib import Path
from types import SimpleNamespace

import pytest

from rekos.adapters import BaseSourceAdapter, MaigretAdapter, SherlockAdapter
from rekos.adapters.registry import default_registry
from rekos.cli import build_parser, main
from rekos.errors import ExternalToolMissingError
from rekos.usernames import username_variants


def _raise_missing_maigret(self, case: str, target: str) -> str:
    raise ExternalToolMissingError("Missing username investigation tool: install maigret.")


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
    assert "investigate" in subcommands
    assert "show-investigation" in subcommands
    assert "snapshot-url" in subcommands
    assert "snapshot-investigation" in subcommands
    assert "sources" in subcommands


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


def test_source_adapter_interface_contract() -> None:
    adapter = SherlockAdapter()
    maigret = MaigretAdapter()

    assert isinstance(adapter, BaseSourceAdapter)
    assert adapter.name == "sherlock"
    assert adapter.description
    assert "username" in adapter.supported_target_types
    assert adapter.passive_only is True
    assert adapter.external_dependencies == ("sherlock",)
    assert isinstance(maigret, BaseSourceAdapter)
    assert maigret.name == "maigret"
    assert maigret.description
    assert "username" in maigret.supported_target_types
    assert maigret.passive_only is True
    assert maigret.external_dependencies == ("maigret",)


def test_source_adapter_registry_contains_initial_sources() -> None:
    registry = default_registry()

    sources = {adapter.name: adapter for adapter in registry.list()}

    assert sorted(sources) == [
        "crtsh_domain",
        "http_snapshot",
        "rdap_domain",
        "sherlock_username",
        "wayback_url",
    ]
    assert sources["sherlock_username"].supported_target_types == ("username",)
    assert sources["sherlock_username"].external_dependencies == ("sherlock",)
    assert sources["http_snapshot"].supported_target_types == ("url",)
    assert sources["http_snapshot"].external_dependencies == ()
    assert sources["rdap_domain"].supported_target_types == ("domain",)
    assert sources["crtsh_domain"].supported_target_types == ("domain",)
    assert sources["wayback_url"].supported_target_types == ("url", "domain")


def test_sources_check_reports_dependency_status(monkeypatch, capsys) -> None:
    monkeypatch.setattr("rekos.adapters.base.shutil.which", lambda _dependency: None)

    assert main(["sources", "check"]) == 0

    output = capsys.readouterr().out
    assert "http_snapshot:" in output
    assert "Dependencies: none" in output
    assert "sherlock_username:" in output
    assert "sherlock: missing" in output


def test_sources_run_missing_dependency(tmp_path: Path, monkeypatch, capsys) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setattr("rekos.adapters.base.shutil.which", lambda _dependency: None)

    assert main(["new-case", "case-source-missing"]) == 0
    assert main(["sources", "run", "case-source-missing", "sherlock_username", "alice"]) == 1

    captured = capsys.readouterr()
    assert "Missing dependencies for sherlock_username: sherlock" in captured.err


def test_sherlock_adapter_parses_output() -> None:
    adapter = SherlockAdapter()

    results = adapter.parse_results(
        "alice",
        """
        [+] Twitter: https://twitter.com/alice
        [+] GitHub: https://github.com/alice
        duplicate https://github.com/alice
        """,
    )

    assert [result.source for result in results] == ["sherlock", "sherlock"]
    assert [result.target for result in results] == ["alice", "alice"]
    assert [result.url for result in results] == [
        "https://twitter.com/alice",
        "https://github.com/alice",
    ]
    assert [result.platform for result in results] == ["twitter", "github"]
    assert [result.confidence for result in results] == ["medium", "medium"]


def test_maigret_adapter_parses_output() -> None:
    adapter = MaigretAdapter()

    results = adapter.parse_results(
        "alice",
        """
        [+] Reddit: https://reddit.com/user/alice
        [+] GitLab: https://gitlab.com/alice).
        duplicate https://gitlab.com/alice
        """,
    )

    assert [result.source for result in results] == ["maigret", "maigret"]
    assert [result.target for result in results] == ["alice", "alice"]
    assert [result.url for result in results] == [
        "https://reddit.com/user/alice",
        "https://gitlab.com/alice",
    ]
    assert [result.platform for result in results] == ["reddit", "gitlab"]
    assert [result.confidence for result in results] == ["medium", "medium"]


def test_maigret_adapter_missing_tool(monkeypatch) -> None:
    monkeypatch.setattr("rekos.adapters.maigret.shutil.which", lambda _tool: None)

    with pytest.raises(ExternalToolMissingError, match="maigret"):
        MaigretAdapter().run("case", "alice")


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


def test_investigate_username_with_mocked_sherlock(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setattr("rekos.adapters.sherlock.shutil.which", lambda tool: f"/usr/bin/{tool}")
    monkeypatch.setattr(MaigretAdapter, "run", _raise_missing_maigret)
    monkeypatch.setattr("rekos.osint.shutil.which", lambda tool: f"/usr/bin/{tool}")
    calls: list[list[str]] = []

    def fake_run(cmd, check, capture_output, text, timeout):
        calls.append(cmd)
        assert check is False
        assert capture_output is True
        assert text is True
        assert timeout == 120
        assert cmd[:3] == ["/usr/bin/sherlock", "--print-found", "--"]
        username = cmd[3]
        return SimpleNamespace(
            returncode=0,
            stdout=f"[+] Found: https://profiles.example/{username}\n",
            stderr="",
        )

    monkeypatch.setattr("rekos.osint.subprocess.run", fake_run)

    assert main(["new-case", "case-investigate"]) == 0
    assert main(["investigate", "username", "case-investigate", "Alice.Smith"]) == 0

    output = capsys.readouterr().out
    assert "Completed username investigation" in output
    assert "Variants: 4" in output
    assert "Discovered profiles: 4" in output
    assert [call[3] for call in calls] == [
        "Alice.Smith",
        "alice.smith",
        "AliceSmith",
        "Alice_Smith",
    ]

    case_folder = tmp_path / "rekos_cases" / "case-investigate"
    exports = sorted((case_folder / "exports").glob("investigate-username-*.txt"))
    assert len(exports) == 4
    assert all("profiles.example" in path.read_text(encoding="utf-8") for path in exports)

    db_path = case_folder / "rekos.db"
    with sqlite3.connect(db_path) as connection:
        entity_rows = connection.execute(
            "SELECT entity_type, value FROM entities ORDER BY id"
        ).fetchall()
        relationship_rows = connection.execute(
            "SELECT relationship_type, confidence FROM relationships ORDER BY id"
        ).fetchall()
        profile_rows = connection.execute(
            """
            SELECT source_username, profile_url, confidence, export_path
            FROM investigation_profiles
            ORDER BY id
            """
        ).fetchall()
        adapter_rows = connection.execute(
            """
            SELECT source, target, url, platform, confidence, raw_reference
            FROM adapter_results
            ORDER BY id
            """
        ).fetchall()
        investigation_row = connection.execute(
            "SELECT username, variant_count, profile_count FROM investigations"
        ).fetchone()
        event_types = [
            row[0]
            for row in connection.execute(
                "SELECT event_type FROM timeline_events ORDER BY id"
            ).fetchall()
        ]

    assert investigation_row == ("Alice.Smith", 4, 4)
    assert [row[0] for row in entity_rows].count("username") == 4
    assert [row[0] for row in entity_rows].count("url") == 4
    assert [row[0] for row in relationship_rows].count("possible_match") == 3
    assert [row[0] for row in relationship_rows].count("discovered_from") == 4
    assert [row[0] for row in relationship_rows].count("same_target") == 4
    assert [row[1] for row in profile_rows] == [
        "https://profiles.example/Alice.Smith",
        "https://profiles.example/alice.smith",
        "https://profiles.example/AliceSmith",
        "https://profiles.example/Alice_Smith",
    ]
    assert [row[2] for row in profile_rows] == ["high", "medium", "low", "medium"]
    assert [row[0] for row in adapter_rows] == ["sherlock_username"] * 4
    assert [row[1] for row in adapter_rows] == [
        "Alice.Smith",
        "alice.smith",
        "AliceSmith",
        "Alice_Smith",
    ]
    assert [row[3] for row in adapter_rows] == ["profiles"] * 4
    assert [row[4] for row in adapter_rows] == ["high", "medium", "low", "medium"]
    assert all(row[2] == row[5] for row in adapter_rows)
    assert all(Path(row[3]).exists() for row in profile_rows)
    assert "investigation.completed" in event_types


def test_investigate_username_runs_maigret_and_deduplicates(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setattr("rekos.adapters.sherlock.shutil.which", lambda tool: f"/usr/bin/{tool}")
    monkeypatch.setattr("rekos.adapters.maigret.shutil.which", lambda tool: f"/usr/bin/{tool}")
    monkeypatch.setattr("rekos.osint.shutil.which", lambda tool: f"/usr/bin/{tool}")
    calls: list[list[str]] = []

    def fake_run(cmd, check, capture_output, text, timeout):
        calls.append(cmd)
        assert check is False
        assert capture_output is True
        assert text is True
        assert timeout == 120
        assert cmd[1:3] == ["--print-found", "--"]
        username = cmd[3]
        if cmd[0] == "/usr/bin/sherlock":
            stdout = "\n".join(
                [
                    f"https://profiles.example/{username}",
                    f"https://shared.example/{username}",
                ]
            )
        else:
            assert cmd[0] == "/usr/bin/maigret"
            stdout = "\n".join(
                [
                    f"https://shared.example/{username}",
                    f"https://maigret.example/{username}",
                ]
            )
        return SimpleNamespace(returncode=0, stdout=f"{stdout}\n", stderr="")

    monkeypatch.setattr("rekos.osint.subprocess.run", fake_run)

    assert main(["new-case", "case-maigret-investigate"]) == 0
    assert main(["investigate", "username", "case-maigret-investigate", "alice"]) == 0

    output = capsys.readouterr().out
    assert "Completed username investigation" in output
    assert "Variants: 1" in output
    assert "Discovered profiles: 3" in output
    assert [call[0] for call in calls] == ["/usr/bin/sherlock", "/usr/bin/maigret"]

    case_folder = tmp_path / "rekos_cases" / "case-maigret-investigate"
    assert (case_folder / "exports" / "investigate-username-alice.txt").exists()
    assert (case_folder / "exports" / "investigate-maigret-alice.txt").exists()

    with sqlite3.connect(case_folder / "rekos.db") as connection:
        profile_rows = connection.execute(
            """
            SELECT profile_url, confidence
            FROM investigation_profiles
            ORDER BY id
            """
        ).fetchall()
        adapter_rows = connection.execute(
            """
            SELECT source, target, url, platform, confidence
            FROM adapter_results
            ORDER BY id
            """
        ).fetchall()

    assert profile_rows == [
        ("https://profiles.example/alice", "high"),
        ("https://shared.example/alice", "high"),
        ("https://maigret.example/alice", "high"),
    ]
    assert adapter_rows == [
        ("sherlock_username", "alice", "https://profiles.example/alice", "profiles", "high"),
        ("sherlock_username", "alice", "https://shared.example/alice", "shared", "high"),
        ("maigret", "alice", "https://maigret.example/alice", "maigret", "high"),
    ]


def test_investigate_username_missing_sherlock(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setattr("rekos.adapters.sherlock.shutil.which", lambda _tool: None)

    assert main(["new-case", "case-no-sherlock"]) == 0
    assert main(["investigate", "username", "case-no-sherlock", "alice"]) == 1

    captured = capsys.readouterr()
    assert "Missing username investigation tool" in captured.err


def test_show_investigation_output(tmp_path: Path, monkeypatch, capsys) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setattr("rekos.adapters.sherlock.shutil.which", lambda tool: f"/usr/bin/{tool}")
    monkeypatch.setattr(MaigretAdapter, "run", _raise_missing_maigret)
    monkeypatch.setattr("rekos.osint.shutil.which", lambda tool: f"/usr/bin/{tool}")

    def fake_run(cmd, check, capture_output, text, timeout):
        username = cmd[3]
        return SimpleNamespace(
            returncode=0,
            stdout=f"https://profiles.example/{username}\n",
            stderr="",
        )

    monkeypatch.setattr("rekos.osint.subprocess.run", fake_run)

    assert main(["new-case", "case-show-investigation"]) == 0
    assert main(["investigate", "username", "case-show-investigation", "Alice.Smith"]) == 0
    capsys.readouterr()

    assert main(["show-investigation", "case-show-investigation"]) == 0

    output = capsys.readouterr().out
    assert "Username: Alice.Smith" in output
    assert "Discovered profiles: 4" in output
    assert "https://profiles.example/Alice.Smith (high) from Alice.Smith" in output
    assert "https://profiles.example/alice.smith (medium) from alice.smith" in output
    assert "Graph entities: 8" in output
    assert "Graph relationships: 11" in output
    assert "Timeline events:" in output


def test_report_renders_investigation_summary(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setattr("rekos.adapters.sherlock.shutil.which", lambda tool: f"/usr/bin/{tool}")
    monkeypatch.setattr(MaigretAdapter, "run", _raise_missing_maigret)
    monkeypatch.setattr("rekos.osint.shutil.which", lambda tool: f"/usr/bin/{tool}")

    def fake_run(cmd, check, capture_output, text, timeout):
        username = cmd[3]
        return SimpleNamespace(
            returncode=0,
            stdout=f"https://profiles.example/{username}\n",
            stderr="",
        )

    monkeypatch.setattr("rekos.osint.subprocess.run", fake_run)

    assert main(["new-case", "case-investigation-report"]) == 0
    assert main(["investigate", "username", "case-investigation-report", "Alice.Smith"]) == 0
    capsys.readouterr()

    assert main(["report", "case-investigation-report"]) == 0

    output = capsys.readouterr().out
    assert "## Investigations" in output
    assert "Username: Alice.Smith" in output
    assert "Discovered profiles: 4" in output
    assert "https://profiles.example/Alice.Smith (high, from Alice.Smith)" in output
    assert "https://profiles.example/AliceSmith (low, from AliceSmith)" in output


class FakeHttpResponse:
    def __init__(self, status: int = 200, body: bytes = b"<html>ok</html>") -> None:
        self.status = status
        self.headers = {"Content-Type": "text/html; charset=utf-8", "X-Test": "yes"}
        self._body = body

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, traceback) -> None:
        return None

    def read(self, _limit: int) -> bytes:
        return self._body


def test_sources_run_http_snapshot_with_mocked_http(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    requested_urls: list[str] = []

    def fake_urlopen(request, timeout):
        requested_urls.append(request.full_url)
        assert timeout == 15
        return FakeHttpResponse(200, b"<html>source</html>")

    monkeypatch.setattr("rekos.snapshots.urlopen", fake_urlopen)
    monkeypatch.setattr("rekos.snapshots.importlib.util.find_spec", lambda _name: None)

    assert main(["new-case", "case-source-run"]) == 0
    assert main(
        [
            "sources",
            "run",
            "case-source-run",
            "http_snapshot",
            "https://profiles.example/alice",
        ]
    ) == 0

    output = capsys.readouterr().out
    assert "Ran source" in output
    assert "http_snapshot" in output
    assert "Results: 1" in output
    assert requested_urls == ["https://profiles.example/alice"]

    db_path = tmp_path / "rekos_cases" / "case-source-run" / "rekos.db"
    with sqlite3.connect(db_path) as connection:
        adapter_row = connection.execute(
            """
            SELECT source, target, url, platform, confidence
            FROM adapter_results
            """
        ).fetchone()
        snapshot_count = connection.execute("SELECT COUNT(*) FROM snapshots").fetchone()[0]
        evidence_count = connection.execute("SELECT COUNT(*) FROM evidence").fetchone()[0]

    assert adapter_row == (
        "http_snapshot",
        "https://profiles.example/alice",
        "https://profiles.example/alice",
        "profiles",
        "high",
    )
    assert snapshot_count == 1
    assert evidence_count == 1


def test_sources_run_rdap_domain_with_mocked_http(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    rdap_payload = {
        "objectClassName": "domain",
        "ldhName": "example.com",
        "links": [{"href": "https://rdap.example/entity/abc"}],
    }
    requested_urls: list[str] = []

    def fake_urlopen(request, timeout):
        requested_urls.append(request.full_url)
        assert timeout == 15
        return FakeHttpResponse(200, json.dumps(rdap_payload).encode("utf-8"))

    monkeypatch.setattr("rekos.adapters.web_osint.urlopen", fake_urlopen)

    assert main(["new-case", "case-rdap-source"]) == 0
    assert main(["sources", "run", "case-rdap-source", "rdap_domain", "example.com"]) == 0

    output = capsys.readouterr().out
    assert "Ran source" in output
    assert "rdap_domain" in output
    assert requested_urls == ["https://rdap.org/domain/example.com"]

    case_folder = tmp_path / "rekos_cases" / "case-rdap-source"
    assert list((case_folder / "exports" / "sources").glob("*rdap_domain*.txt"))
    with sqlite3.connect(case_folder / "rekos.db") as connection:
        entities = connection.execute(
            "SELECT entity_type, value FROM entities ORDER BY id"
        ).fetchall()
        adapter_sources = [
            row[0]
            for row in connection.execute(
                "SELECT source FROM adapter_results ORDER BY id"
            ).fetchall()
        ]
        event_types = [
            row[0]
            for row in connection.execute(
                "SELECT event_type FROM timeline_events ORDER BY id"
            ).fetchall()
        ]

    assert ("domain", "example.com") in entities
    assert ("url", "https://rdap.example/entity/abc") in entities
    assert adapter_sources == ["rdap_domain", "rdap_domain"]
    assert "source.run" in event_types


def test_sources_run_crtsh_domain_with_mocked_http(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    crtsh_payload = [
        {"name_value": "www.example.com\n*.api.example.com\nother.test"},
        {"common_name": "mail.example.com"},
    ]

    def fake_urlopen(request, timeout):
        assert request.full_url.startswith("https://crt.sh/?")
        assert timeout == 15
        return FakeHttpResponse(200, json.dumps(crtsh_payload).encode("utf-8"))

    monkeypatch.setattr("rekos.adapters.web_osint.urlopen", fake_urlopen)

    assert main(["new-case", "case-crtsh-source"]) == 0
    assert main(["sources", "run", "case-crtsh-source", "crtsh_domain", "example.com"]) == 0

    output = capsys.readouterr().out
    assert "crtsh_domain" in output
    case_folder = tmp_path / "rekos_cases" / "case-crtsh-source"
    assert list((case_folder / "exports" / "sources").glob("*crtsh_domain*.txt"))
    with sqlite3.connect(case_folder / "rekos.db") as connection:
        entities = connection.execute(
            "SELECT entity_type, value FROM entities ORDER BY id"
        ).fetchall()
        relationships = connection.execute(
            "SELECT relationship_type, confidence FROM relationships ORDER BY id"
        ).fetchall()
        adapter_urls = [
            row[0]
            for row in connection.execute(
                "SELECT url FROM adapter_results ORDER BY id"
            ).fetchall()
        ]

    assert ("domain", "example.com") in entities
    assert ("domain", "www.example.com") in entities
    assert ("domain", "api.example.com") in entities
    assert ("domain", "mail.example.com") in entities
    assert relationships == [
        ("extracted_from", "medium"),
        ("extracted_from", "medium"),
        ("extracted_from", "medium"),
    ]
    assert adapter_urls == [
        "https://www.example.com",
        "https://api.example.com",
        "https://mail.example.com",
    ]


def test_sources_run_wayback_url_with_mocked_http(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    wayback_payload = [
        ["timestamp", "original", "statuscode", "mimetype"],
        ["20200101000000", "https://example.com/page", "200", "text/html"],
    ]
    requested_urls: list[str] = []

    def fake_urlopen(request, timeout):
        requested_urls.append(request.full_url)
        assert timeout == 15
        return FakeHttpResponse(200, json.dumps(wayback_payload).encode("utf-8"))

    monkeypatch.setattr("rekos.adapters.web_osint.urlopen", fake_urlopen)

    assert main(["new-case", "case-wayback-source"]) == 0
    assert main(["sources", "run", "case-wayback-source", "wayback_url", "example.com"]) == 0

    output = capsys.readouterr().out
    assert "wayback_url" in output
    assert requested_urls[0].startswith("https://web.archive.org/cdx?")
    archive_url = "https://web.archive.org/web/20200101000000/https://example.com/page"
    case_folder = tmp_path / "rekos_cases" / "case-wayback-source"
    assert list((case_folder / "exports" / "sources").glob("*wayback_url*.txt"))
    with sqlite3.connect(case_folder / "rekos.db") as connection:
        entities = connection.execute(
            "SELECT entity_type, value FROM entities ORDER BY id"
        ).fetchall()
        relationship = connection.execute(
            "SELECT relationship_type, confidence FROM relationships"
        ).fetchone()
        adapter_row = connection.execute(
            "SELECT source, target, url, platform FROM adapter_results"
        ).fetchone()

    assert ("domain", "example.com") in entities
    assert ("url", archive_url) in entities
    assert relationship == ("extracted_from", "medium")
    assert adapter_row == ("wayback_url", "example.com", archive_url, "wayback")


def test_snapshot_url_with_mocked_http_creates_artifacts_evidence_and_timeline(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    requested_urls: list[str] = []

    def fake_urlopen(request, timeout):
        requested_urls.append(request.full_url)
        assert timeout == 15
        return FakeHttpResponse(200, b"<html><title>Public</title></html>")

    monkeypatch.setattr("rekos.snapshots.urlopen", fake_urlopen)
    monkeypatch.setattr("rekos.snapshots.importlib.util.find_spec", lambda _name: None)

    assert main(["new-case", "case-snapshot"]) == 0
    assert main(["snapshot-url", "case-snapshot", "https://profiles.example/alice"]) == 0

    output = capsys.readouterr().out
    assert "Captured snapshot" in output
    assert "Screenshot: not captured" in output
    assert requested_urls == ["https://profiles.example/alice"]

    case_folder = tmp_path / "rekos_cases" / "case-snapshot"
    snapshot_files = sorted((case_folder / "exports" / "snapshots").iterdir())
    assert any(path.name.endswith("-headers.json") for path in snapshot_files)
    assert any(path.name.endswith("-body.html") for path in snapshot_files)
    assert not any(path.name.endswith("-screenshot.png") for path in snapshot_files)

    db_path = case_folder / "rekos.db"
    with sqlite3.connect(db_path) as connection:
        snapshot_row = connection.execute(
            """
            SELECT url, status_code, headers_path, body_path, screenshot_path, evidence_id
            FROM snapshots
            """
        ).fetchone()
        evidence_row = connection.execute(
            "SELECT type, path, source_url FROM evidence"
        ).fetchone()
        entity_row = connection.execute(
            "SELECT entity_type, value FROM entities"
        ).fetchone()
        event_types = [
            row[0]
            for row in connection.execute(
                "SELECT event_type FROM timeline_events ORDER BY id"
            ).fetchall()
        ]

    assert snapshot_row[0:2] == ("https://profiles.example/alice", 200)
    assert Path(snapshot_row[2]).exists()
    assert Path(snapshot_row[3]).read_text(encoding="utf-8") == "<html><title>Public</title></html>"
    assert snapshot_row[4] == ""
    assert evidence_row[0] == "url_snapshot"
    assert evidence_row[1] == snapshot_row[3]
    assert evidence_row[2] == "https://profiles.example/alice"
    assert entity_row == ("url", "https://profiles.example/alice")
    assert "snapshot.created" in event_types


def test_snapshot_url_skips_recent_duplicate(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    calls = 0

    def fake_urlopen(request, timeout):
        nonlocal calls
        calls += 1
        return FakeHttpResponse()

    monkeypatch.setattr("rekos.snapshots.urlopen", fake_urlopen)
    monkeypatch.setattr("rekos.snapshots.importlib.util.find_spec", lambda _name: None)

    assert main(["new-case", "case-snapshot-duplicate"]) == 0
    assert main(["snapshot-url", "case-snapshot-duplicate", "https://profiles.example/alice"]) == 0
    assert main(["snapshot-url", "case-snapshot-duplicate", "https://profiles.example/alice"]) == 0

    output = capsys.readouterr().out
    assert "Skipped recent snapshot" in output
    assert calls == 1

    db_path = tmp_path / "rekos_cases" / "case-snapshot-duplicate" / "rekos.db"
    with sqlite3.connect(db_path) as connection:
        snapshot_count = connection.execute("SELECT COUNT(*) FROM snapshots").fetchone()[0]
    assert snapshot_count == 1


def test_snapshot_investigation_continues_on_individual_errors(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setattr("rekos.adapters.sherlock.shutil.which", lambda tool: f"/usr/bin/{tool}")
    monkeypatch.setattr(MaigretAdapter, "run", _raise_missing_maigret)
    monkeypatch.setattr("rekos.osint.shutil.which", lambda tool: f"/usr/bin/{tool}")
    monkeypatch.setattr("rekos.snapshots.importlib.util.find_spec", lambda _name: None)

    def fake_run(cmd, check, capture_output, text, timeout):
        username = cmd[3]
        return SimpleNamespace(
            returncode=0,
            stdout=f"https://profiles.example/{username}\n",
            stderr="",
        )

    def fake_urlopen(request, timeout):
        if request.full_url.endswith("/AliceSmith"):
            raise OSError("temporary failure")
        return FakeHttpResponse(200, f"<html>{request.full_url}</html>".encode("utf-8"))

    monkeypatch.setattr("rekos.osint.subprocess.run", fake_run)
    monkeypatch.setattr("rekos.snapshots.urlopen", fake_urlopen)

    assert main(["new-case", "case-snapshot-investigation"]) == 0
    assert main(["investigate", "username", "case-snapshot-investigation", "Alice.Smith"]) == 0
    capsys.readouterr()

    assert main(["snapshot-investigation", "case-snapshot-investigation"]) == 0

    output = capsys.readouterr().out
    assert "Captured: 3" in output
    assert "Skipped: 0" in output
    assert "Failed: 1" in output
    assert "temporary failure" in output

    db_path = tmp_path / "rekos_cases" / "case-snapshot-investigation" / "rekos.db"
    with sqlite3.connect(db_path) as connection:
        snapshot_count = connection.execute("SELECT COUNT(*) FROM snapshots").fetchone()[0]
        evidence_count = connection.execute("SELECT COUNT(*) FROM evidence").fetchone()[0]
    assert snapshot_count == 3
    assert evidence_count == 3


def test_report_renders_snapshot_section(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))

    def fake_urlopen(request, timeout):
        return FakeHttpResponse(200, b"<html>report</html>")

    monkeypatch.setattr("rekos.snapshots.urlopen", fake_urlopen)
    monkeypatch.setattr("rekos.snapshots.importlib.util.find_spec", lambda _name: None)

    assert main(["new-case", "case-snapshot-report"]) == 0
    assert main(["snapshot-url", "case-snapshot-report", "https://profiles.example/alice"]) == 0
    capsys.readouterr()

    assert main(["report", "case-snapshot-report"]) == 0

    output = capsys.readouterr().out
    assert "## Snapshots" in output
    assert "URL: https://profiles.example/alice" in output
    assert "HTTP status: 200" in output
    assert "Body:" in output
    assert "Evidence:" in output


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
