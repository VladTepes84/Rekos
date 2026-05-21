from __future__ import annotations

import argparse
import json
import sqlite3
import sys
import tomllib
import uuid
import zipfile
from pathlib import Path
from types import SimpleNamespace
from urllib.error import HTTPError

import pytest

from rekos.adapters import (
    AdapterResult,
    BaseSourceAdapter,
    MaigretAdapter,
    SherlockAdapter,
    SourceRunResult,
    WmnUsernameAdapter,
)
from rekos.adapters.registry import default_registry
from rekos.adapters.web_osint import normalize_url_or_domain
from rekos.banner import render_banner
from rekos.cli import build_parser, main
from rekos.errors import ExternalToolExecutionError, ExternalToolMissingError
from rekos.snapshots import normalize_public_url
from rekos.storage import CaseStore, quality_label
from rekos.usernames import username_variants


def _raise_missing_maigret(self, case: str, target: str) -> str:
    raise ExternalToolMissingError("Missing username investigation tool: install maigret.")


def _empty_wmn(self, case: str, target: str) -> str:
    return json.dumps({"source": "wmn_username", "target": target, "results": []})


class FakeSourceAdapter:
    def __init__(
        self,
        name: str,
        *,
        missing: tuple[str, ...] = (),
        fail: bool = False,
    ) -> None:
        self.name = name
        self.description = f"Fake {name}"
        self.supported_target_types = ("domain", "url")
        self.passive_only = True
        self.external_dependencies = missing
        self._missing = missing
        self._fail = fail

    def missing_dependencies(self) -> list[str]:
        return list(self._missing)

    def execute(self, case: str, target: str, store) -> SourceRunResult:
        if self._fail:
            raise ExternalToolExecutionError("temporary source failure")
        root_type = "url" if target.startswith(("http://", "https://")) else "domain"
        root = store.ensure_entity(case, root_type, target, f"{self.name} target")
        url = f"https://{self.name}.example/{target.replace('://', '/')}"
        related = store.ensure_entity(case, "url", url, f"{self.name} result")
        store.relate_entities(
            case,
            related.entity_id,
            root.entity_id,
            "extracted_from",
            "medium",
            f"{self.name} mocked result",
        )
        result = AdapterResult(
            source=self.name,
            target=target,
            url=url,
            platform="mocked",
            confidence="medium",
            raw_reference=url,
        )
        store.add_adapter_results(case, [result])
        store.add_timeline_event(case, "source.run", f"Ran source {self.name} for {target}")
        return SourceRunResult(
            source=self.name,
            target=target,
            raw_output=url,
            results=[result],
            artifacts=[],
        )


class FakeSourceRegistry:
    def __init__(self, adapters: dict[str, FakeSourceAdapter]) -> None:
        self.adapters = adapters

    def get(self, name: str) -> FakeSourceAdapter:
        return self.adapters[name]


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


def test_export_case_creates_zip_with_manifest(tmp_path: Path, monkeypatch, capsys) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    archive = tmp_path / "case-export.zip"

    assert main(["new-case", "case-export"]) == 0
    assert main(["add-note", "case-export", "export note"]) == 0
    assert main(["export-case", "case-export", "--output", str(archive)]) == 0

    output = capsys.readouterr().out
    assert "Exported case" in output
    assert archive.exists()
    with zipfile.ZipFile(archive) as exported:
        names = set(exported.namelist())

    assert "case-export/rekos.db" in names
    assert "case-export/manifest.json" in names
    assert "case-export/manifest.sha256" in names


def test_validation_module_smoke(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    from rekos.validation import validate_case

    store = CaseStore()
    store.create_case("case-validation-module")

    result = validate_case("case-validation-module", store)

    assert result.ok


def test_case_export_module_smoke(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    from rekos.case_export import export_case

    store = CaseStore()
    store.create_case("case-export-module")
    archive = tmp_path / "case-export-module.zip"

    result = export_case("case-export-module", archive, store)

    assert result.output_path == archive
    with zipfile.ZipFile(archive) as exported:
        names = set(exported.namelist())
    assert "rekos.db" in names
    assert "manifest.json" in names
    assert "manifest.sha256" in names


def test_passive_osint_commands_are_registered() -> None:
    parser = build_parser()
    subparser_action = next(
        action
        for action in parser._actions
        if isinstance(action, argparse._SubParsersAction)
    )
    subcommands = subparser_action.choices

    assert "metadata" in subcommands
    assert "quickstart" in subcommands
    assert "version" in subcommands
    assert "username-scan" in subcommands
    assert "add-entity" in subcommands
    assert "relate-entities" in subcommands
    assert "list-entities" in subcommands
    assert "graph-summary" in subcommands
    assert "username-variants" in subcommands
    assert "add-username-target" in subcommands
    assert "investigate" in subcommands
    assert "show-investigation" in subcommands
    assert "findings" in subcommands
    assert "score" in subcommands
    assert "snapshot-url" in subcommands
    assert "snapshot-investigation" in subcommands
    assert "search" in subcommands
    assert "list-targets" in subcommands
    assert "list-sources" in subcommands
    assert "export-case" in subcommands
    assert "sources" in subcommands


def test_quickstart_command_outputs_onboarding(capsys) -> None:
    assert main(["quickstart"]) == 0

    output = capsys.readouterr().out
    assert "REKOS READY" in output
    assert "pipx install rekos" in output
    assert "rekos[full]" not in output
    assert "1. " not in output
    assert "2. " not in output
    assert "rekos new-case my_case" in output
    assert "rekos investigate username my_case username" in output
    assert "rekos investigate domain my_case example.com" in output
    assert "rekos findings my_case" in output
    assert "rekos score my_case" in output
    assert "rekos graph-summary my_case" in output
    assert "rekos export-case my_case --output my_case.zip" in output
    assert "Common commands:" not in output
    assert "Investigations:" not in output
    assert "[+] Terminal-native. Passive OSINT. Local-first." in output
    assert "REKOS 1.3.2" not in output
    assert "Version: 1.3.2" in output


def test_no_args_outputs_quickstart(capsys) -> None:
    assert main([]) == 0
    no_args_output = capsys.readouterr().out

    assert main(["quickstart"]) == 0
    quickstart_output = capsys.readouterr().out

    assert no_args_output == quickstart_output
    assert "REKOS READY" in no_args_output
    assert "rekos new-case my_case" in no_args_output


def test_version_command_outputs_package_version(capsys) -> None:
    assert main(["version"]) == 0

    output = capsys.readouterr().out
    assert output == "rekos 1.3.2\n"
    assert "REKOS READY" not in output
    assert "██████" not in output


def test_banner_renderer_falls_back_without_pyfiglet(monkeypatch) -> None:
    monkeypatch.setitem(sys.modules, "pyfiglet", None)

    banner = render_banner()

    assert banner is not None


def test_help_output_has_no_banner(capsys) -> None:
    with pytest.raises(SystemExit) as exc_info:
        main(["--help"])

    assert exc_info.value.code == 0
    output = capsys.readouterr().out
    assert "REKOS READY" not in output
    assert "quickstart" in output
    assert "investigate" in output


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
    assert maigret.description
    assert "username" in maigret.supported_target_types
    assert maigret.passive_only is True
    assert maigret.name == "maigret_username"
    assert maigret.external_dependencies == ("maigret",)


def test_source_adapter_registry_contains_initial_sources() -> None:
    registry = default_registry()

    sources = {adapter.name: adapter for adapter in registry.list()}

    assert sorted(sources) == [
        "crtsh_domain",
        "dns_domain",
        "http_snapshot",
        "maigret_username",
        "rdap_domain",
        "sherlock_username",
        "wayback_url",
        "web_domain",
        "wmn_username",
    ]
    assert sources["sherlock_username"].supported_target_types == ("username",)
    assert sources["sherlock_username"].external_dependencies == ("sherlock",)
    assert sources["maigret_username"].supported_target_types == ("username",)
    assert sources["maigret_username"].external_dependencies == ("maigret",)
    assert sources["wmn_username"].supported_target_types == ("username",)
    assert sources["wmn_username"].external_dependencies == ()
    assert sources["http_snapshot"].supported_target_types == ("url",)
    assert sources["http_snapshot"].external_dependencies == ()
    assert sources["dns_domain"].supported_target_types == ("domain",)
    assert sources["dns_domain"].external_dependencies == ()
    assert sources["rdap_domain"].supported_target_types == ("domain",)
    assert sources["web_domain"].supported_target_types == ("domain",)
    assert sources["web_domain"].external_dependencies == ()
    assert sources["crtsh_domain"].supported_target_types == ("domain",)
    assert sources["wayback_url"].supported_target_types == ("url", "domain")


@pytest.mark.parametrize(
    "url",
    [
        "http://localhost",
        "http://localhost.localdomain",
        "http://127.0.0.1",
        "http://127.42.0.1",
        "http://[::1]/",
        "http://10.0.0.10",
        "http://172.16.0.1",
        "http://192.168.1.1",
        "http://169.254.10.1",
        "http://169.254.169.254/latest/meta-data",
        "http://0.0.0.0",
        "http://224.0.0.1",
    ],
)
def test_snapshot_url_rejects_internal_targets(url: str) -> None:
    with pytest.raises(ValueError):
        normalize_public_url(url)


@pytest.mark.parametrize(
    "target",
    [
        "http://localhost",
        "https://127.0.0.1",
        "http://[::1]/",
        "10.0.0.1",
        "192.168.1.20",
        "169.254.169.254",
        "localhost.localdomain",
    ],
)
def test_url_or_domain_normalization_rejects_internal_targets(target: str) -> None:
    with pytest.raises(ValueError):
        normalize_url_or_domain(target)


def test_pyproject_uses_single_public_package() -> None:
    data = tomllib.loads(Path("pyproject.toml").read_text(encoding="utf-8"))
    optional = data["project"]["optional-dependencies"]

    assert "username" not in optional
    assert "full" not in optional
    assert "maigret" not in data["project"]["dependencies"]
    assert data["project"]["name"] == "rekos"


def test_sources_check_reports_dependency_status(monkeypatch, capsys) -> None:
    monkeypatch.setattr("rekos.adapters.base.shutil.which", lambda _dependency: None)
    monkeypatch.setattr("rekos.adapters.maigret._resolve_maigret_command", lambda: None)

    assert main(["sources", "check"]) == 0

    output = capsys.readouterr().out
    assert "http_snapshot:" in output
    assert "Dependencies: none" in output
    assert "sherlock_username:" in output
    assert "sherlock: missing" in output
    assert "maigret_username:" in output
    assert "maigret: missing" in output
    assert "Optional tool missing; REKOS continues without it." in output
    assert "rekos[full]" not in output


def test_sources_check_detects_mocked_maigret_availability(monkeypatch, capsys) -> None:
    monkeypatch.setattr("rekos.adapters.base.shutil.which", lambda _dependency: None)
    monkeypatch.setattr(
        "rekos.adapters.maigret._resolve_maigret_command",
        lambda: ["/pipx/venv/bin/maigret"],
    )

    assert main(["sources", "check"]) == 0

    output = capsys.readouterr().out
    assert "maigret_username:" in output
    assert "maigret: available" in output
    assert "maigret: missing" not in output


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

    assert [result.source for result in results] == ["maigret_username", "maigret_username"]
    assert [result.target for result in results] == ["alice", "alice"]
    assert [result.url for result in results] == [
        "https://reddit.com/user/alice",
        "https://gitlab.com/alice",
    ]
    assert [result.platform for result in results] == ["reddit", "gitlab"]
    assert [result.confidence for result in results] == ["medium", "medium"]


def test_maigret_adapter_missing_tool(monkeypatch) -> None:
    monkeypatch.setattr("rekos.adapters.maigret._resolve_maigret_command", lambda: None)

    with pytest.raises(ExternalToolMissingError, match="maigret"):
        MaigretAdapter().run("case", "alice")


def test_maigret_adapter_runs_module_fallback(monkeypatch) -> None:
    monkeypatch.setattr(
        "rekos.adapters.maigret._resolve_maigret_command",
        lambda: [sys.executable, "-m", "maigret"],
    )
    calls: list[list[str]] = []

    def fake_run(cmd, check, capture_output, text, timeout):
        calls.append(cmd)
        return SimpleNamespace(returncode=0, stdout="https://example.com/alice\n", stderr="")

    monkeypatch.setattr("rekos.osint.subprocess.run", fake_run)

    raw_output = MaigretAdapter().run("case", "alice")

    assert calls == [[sys.executable, "-m", "maigret", "--print-found", "--", "alice"]]
    assert "https://example.com/alice" in raw_output


def test_wmn_adapter_parses_mocked_hit() -> None:
    adapter = WmnUsernameAdapter()
    raw_output = json.dumps(
        {
            "source": "wmn_username",
            "target": "alice",
            "results": [
                {
                    "platform": "GitHub",
                    "url": "https://github.com/alice",
                    "status_code": 200,
                    "hit": True,
                    "error": "",
                },
                {
                    "platform": "Reddit",
                    "url": "https://www.reddit.com/user/alice",
                    "status_code": 404,
                    "hit": False,
                    "error": "",
                },
            ],
        }
    )

    results = adapter.parse_results("alice", raw_output)

    assert results == [
        AdapterResult(
            source="wmn_username",
            target="alice",
            url="https://github.com/alice",
            platform="github",
            confidence="medium",
            raw_reference="HTTP status: 200",
        )
    ]


def test_wmn_source_list_contains_instagram_template() -> None:
    source_list = json.loads(Path("rekos/adapters/wmn_sources.json").read_text(encoding="utf-8"))

    assert {
        "platform": "Instagram",
        "url_template": "https://www.instagram.com/{username}/",
    } in source_list


def test_sources_run_wmn_username_creates_profile_finding(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))

    def fake_urlopen(request, timeout):
        status = 200 if request.full_url == "https://github.com/alice" else 404
        return FakeHttpResponse(status, b"")

    monkeypatch.setattr("rekos.adapters.wmn.urlopen", fake_urlopen)

    assert main(["new-case", "case-wmn-source"]) == 0
    assert main(["sources", "run", "case-wmn-source", "wmn_username", "alice"]) == 0

    output = capsys.readouterr().out
    assert "Ran source" in output
    assert "wmn_username" in output
    assert "Results: 1" in output

    case_folder = tmp_path / "rekos_cases" / "case-wmn-source"
    assert list((case_folder / "exports" / "sources").glob("*wmn_username-alice.txt"))
    with sqlite3.connect(case_folder / "rekos.db") as connection:
        row = connection.execute(
            """
            SELECT type, value, source, confidence, quality_score
            FROM normalized_findings
            """
        ).fetchone()

    assert row[0:4] == (
        "discovered_profile",
        "https://github.com/alice",
        "wmn_username",
        "medium",
    )
    assert row[4] > 0


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
    assert "Graph overview" in output
    assert "Entities: 3" in output
    assert "Relationships: 2" in output
    assert "Entity types" in output
    assert "domain" in output
    assert "username" in output
    assert "Most connected" in output
    assert "Graph links" in output
    assert "Graph links are internal relationships, not unique findings." in output
    assert "example.com" in output
    assert entity_ids[1] not in output


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
    assert "| `email` | a@example.com |" in output
    assert "## Relationships" in output
    assert "| `possible_match` | medium |" in output
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
    assert "| `possible_match` | high |" in output
    assert "| `possible_match` | medium |" in output
    assert "| `possible_match` | low |" in output
    assert "username variant correlation" in output


def test_search_entities_and_findings(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    wayback_payload = [
        ["timestamp", "original", "statuscode", "mimetype"],
        ["20200101000000", "https://example.com/page", "200", "text/html"],
    ]

    def fake_urlopen(request, timeout):
        return FakeHttpResponse(200, json.dumps(wayback_payload).encode("utf-8"))

    monkeypatch.setattr("rekos.adapters.web_osint.urlopen", fake_urlopen)

    assert main(["new-case", "case-search"]) == 0
    assert main(
        [
            "add-entity",
            "case-search",
            "--type",
            "domain",
            "--value",
            "example.com",
            "--note",
            "primary target",
        ]
    ) == 0
    assert main(["sources", "run", "case-search", "wayback_url", "example.com"]) == 0
    capsys.readouterr()

    assert main(["search", "case-search", "example.com"]) == 0

    output = capsys.readouterr().out
    assert "Search Results" in output
    assert "entity" in output
    assert "finding" in output
    assert "domain" in output
    assert "archive_record" in output
    assert "https://example.com/page" in output


def test_search_filters_by_type_source_and_confidence(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    wayback_payload = [
        ["timestamp", "original", "statuscode", "mimetype"],
        ["20200101000000", "https://example.com/page", "200", "text/html"],
    ]

    def fake_urlopen(request, timeout):
        return FakeHttpResponse(200, json.dumps(wayback_payload).encode("utf-8"))

    monkeypatch.setattr("rekos.adapters.web_osint.urlopen", fake_urlopen)

    assert main(["new-case", "case-search-filter"]) == 0
    assert main(
        [
            "add-entity",
            "case-search-filter",
            "--type",
            "domain",
            "--value",
            "example.com",
            "--note",
            "primary target",
        ]
    ) == 0
    assert main(["sources", "run", "case-search-filter", "wayback_url", "example.com"]) == 0
    capsys.readouterr()

    assert main(["search", "case-search-filter", "example.com", "--type", "entity"]) == 0
    entity_output = capsys.readouterr().out
    assert "entity" in entity_output
    assert "primary target" in entity_output
    assert "archive_record" not in entity_output

    assert main(["search", "case-search-filter", "example.com", "--source", "wayback_url"]) == 0
    source_output = capsys.readouterr().out
    assert "archive_record" in source_output
    assert "primary target" not in source_output

    assert main(["search", "case-search-filter", "example.com", "--confidence", "medium"]) == 0
    confidence_output = capsys.readouterr().out
    assert "archive_record" in confidence_output
    assert "medium" in confidence_output

    assert main(["search", "case-search-filter", "example.com", "--confidence", "high"]) == 0
    high_output = capsys.readouterr().out
    assert "No results found" in high_output


def test_list_targets_groups_target_like_entities(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))

    assert main(["new-case", "case-list-targets"]) == 0
    assert main(["add-entity", "case-list-targets", "--type", "username", "--value", "alice"]) == 0
    assert main(["add-entity", "case-list-targets", "--type", "domain", "--value", "example.com"]) == 0
    assert main(["add-entity", "case-list-targets", "--type", "note", "--value", "internal-note"]) == 0
    capsys.readouterr()

    assert main(["list-targets", "case-list-targets"]) == 0

    output = capsys.readouterr().out
    assert "Targets" in output
    assert "username" in output
    assert "alice" in output
    assert "domain" in output
    assert "example.com" in output
    assert "internal-note" not in output


def test_list_sources_shows_status_findings_and_errors(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    registry = FakeSourceRegistry(
        {
            "rdap_domain": FakeSourceAdapter("rdap_domain"),
            "dns_domain": FakeSourceAdapter("dns_domain", fail=True),
            "web_domain": FakeSourceAdapter("web_domain"),
            "crtsh_domain": FakeSourceAdapter("crtsh_domain"),
        }
    )
    monkeypatch.setattr("rekos.investigation.default_registry", lambda: registry)

    assert main(["new-case", "case-list-sources"]) == 0
    assert main(["investigate", "domain", "case-list-sources", "example.com"]) == 0
    capsys.readouterr()

    assert main(["list-sources", "case-list-sources"]) == 0

    output = capsys.readouterr().out
    assert "Source Runs" in output
    assert "rdap_domain" in output
    assert "ok" in output
    assert "dns_domain" in output
    assert "failed" in output
    assert "temporary source failure" in output
    assert "web_domain" in output


def test_source_runs_keep_per_run_counts(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    store = CaseStore()
    store.create_case("case-source-run-counts")
    store.add_source_run("case-source-run-counts", "web_domain", "a.example", "ok", 1)
    store.add_source_run("case-source-run-counts", "web_domain", "b.example", "ok", 3)

    runs = store.source_runs("case-source-run-counts")

    assert [(run.target, run.findings_count) for run in runs] == [
        ("a.example", 1),
        ("b.example", 3),
    ]


def test_investigate_username_with_mocked_sherlock(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setattr("rekos.adapters.sherlock.shutil.which", lambda tool: f"/usr/bin/{tool}")
    monkeypatch.setattr(MaigretAdapter, "run", _raise_missing_maigret)
    monkeypatch.setattr(WmnUsernameAdapter, "run", _empty_wmn)
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
    assert "Next steps:" in output
    assert "rekos findings case-investigate" in output
    assert "rekos findings case-investigate --verbose" in output
    assert "rekos graph-summary case-investigate" in output
    assert "rekos export-case case-investigate --output case-investigate.zip" in output
    assert "Confirming sources" not in output
    assert "Reason:" not in output
    assert "quality" not in output
    assert "finding_" not in output
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
        finding_rows = connection.execute(
            """
            SELECT type, value, source, confidence, raw_reference
            FROM normalized_findings
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
    assert [row[0] for row in entity_rows].count("platform") == 1
    assert [row[0] for row in entity_rows].count("source") == 1
    assert [row[0] for row in relationship_rows].count("possible_match") == 3
    assert [row[0] for row in relationship_rows].count("discovered_from") == 4
    assert [row[0] for row in relationship_rows].count("same_target") == 4
    assert [row[0] for row in relationship_rows].count("discovered_on") == 4
    assert [row[0] for row in relationship_rows].count("hosts_profile") == 4
    assert [row[0] for row in relationship_rows].count("produced") == 4
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
    assert [row[0] for row in finding_rows] == ["discovered_profile"] * 4
    assert [row[2] for row in finding_rows] == ["sherlock_username"] * 4
    assert [row[3] for row in finding_rows] == ["high", "medium", "low", "medium"]
    assert all(row[1] == row[4] for row in finding_rows)
    assert all(Path(row[3]).exists() for row in profile_rows)
    assert "investigation.completed" in event_types

    assert main(["investigate", "username", "case-investigate", "Alice.Smith"]) == 0
    capsys.readouterr()
    with sqlite3.connect(db_path) as connection:
        rerun_entity_counts = dict(
            connection.execute(
                "SELECT entity_type, COUNT(*) FROM entities GROUP BY entity_type"
            ).fetchall()
        )
        rerun_relationship_counts = dict(
            connection.execute(
                "SELECT relationship_type, COUNT(*) FROM relationships GROUP BY relationship_type"
            ).fetchall()
        )

    assert rerun_entity_counts == {
        "platform": 1,
        "source": 1,
        "url": 4,
        "username": 4,
    }
    assert rerun_relationship_counts == {
        "discovered_from": 4,
        "discovered_on": 4,
        "hosts_profile": 4,
        "possible_match": 3,
        "produced": 4,
        "same_target": 4,
    }

    assert main(["graph-summary", "case-investigate"]) == 0
    graph_output = capsys.readouterr().out
    assert "platform" in graph_output
    assert "source" in graph_output


def test_investigate_username_runs_maigret_and_deduplicates(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setattr("rekos.adapters.sherlock.shutil.which", lambda tool: f"/usr/bin/{tool}")
    monkeypatch.setattr("rekos.adapters.maigret.shutil.which", lambda tool: f"/usr/bin/{tool}")
    monkeypatch.setattr(WmnUsernameAdapter, "run", _empty_wmn)
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
    assert (case_folder / "exports" / "investigate-maigret_username-alice.txt").exists()

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
        finding_rows = connection.execute(
            """
            SELECT type, value, source, confidence
            FROM normalized_findings
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
        ("maigret_username", "alice", "https://shared.example/alice", "shared", "high"),
        ("maigret_username", "alice", "https://maigret.example/alice", "maigret", "high"),
    ]
    assert finding_rows == [
        ("discovered_profile", "https://profiles.example/alice", "sherlock_username", "high"),
        ("discovered_profile", "https://shared.example/alice", "sherlock_username", "high"),
        ("discovered_profile", "https://shared.example/alice", "maigret_username", "high"),
        ("discovered_profile", "https://maigret.example/alice", "maigret_username", "high"),
    ]


def test_investigate_username_records_missing_maigret_source(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setattr("rekos.adapters.sherlock.shutil.which", lambda tool: f"/usr/bin/{tool}")
    monkeypatch.setattr(MaigretAdapter, "run", _raise_missing_maigret)
    monkeypatch.setattr(WmnUsernameAdapter, "run", _empty_wmn)
    monkeypatch.setattr("rekos.osint.shutil.which", lambda tool: f"/usr/bin/{tool}")

    def fake_run(cmd, check, capture_output, text, timeout):
        username = cmd[3]
        return SimpleNamespace(
            returncode=0,
            stdout=f"https://profiles.example/{username}\n",
            stderr="",
        )

    monkeypatch.setattr("rekos.osint.subprocess.run", fake_run)

    assert main(["new-case", "case-maigret-missing-investigate"]) == 0
    assert main(["investigate", "username", "case-maigret-missing-investigate", "alice"]) == 0

    output = capsys.readouterr().out
    assert "Warnings:" in output
    assert "Missing dependencies for maigret_username" in output

    with sqlite3.connect(tmp_path / "rekos_cases" / "case-maigret-missing-investigate" / "rekos.db") as connection:
        row = connection.execute(
            "SELECT source, error FROM source_investigation_errors"
        ).fetchone()
        summary = connection.execute(
            "SELECT skipped_count, failed_count FROM source_investigations"
        ).fetchone()

    assert row[0] == "maigret_username"
    assert "maigret" in row[1]
    assert summary == (1, 0)


def test_investigate_username_prints_clean_maigret_runtime_warning(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setattr("rekos.adapters.sherlock.shutil.which", lambda tool: f"/usr/bin/{tool}")
    monkeypatch.setattr("rekos.osint.shutil.which", lambda tool: f"/usr/bin/{tool}")
    monkeypatch.setattr(WmnUsernameAdapter, "run", _empty_wmn)

    def fake_sherlock(cmd, check, capture_output, text, timeout):
        username = cmd[3]
        return SimpleNamespace(
            returncode=0,
            stdout=f"https://profiles.example/{username}\n",
            stderr="",
        )

    def fail_maigret(self, case: str, target: str) -> str:
        raise ExternalToolExecutionError(
            "maigret failed: Traceback (most recent call last): upstream details"
        )

    monkeypatch.setattr("rekos.osint.subprocess.run", fake_sherlock)
    monkeypatch.setattr(MaigretAdapter, "run", fail_maigret)

    assert main(["new-case", "case-maigret-runtime-failure"]) == 0
    assert main(["investigate", "username", "case-maigret-runtime-failure", "peppespan00ac"]) == 0

    output = capsys.readouterr().out
    assert "- Maigret source failed for peppespan00ac; continuing with other sources." in output
    assert "Traceback" not in output
    assert "upstream details" not in output

    with sqlite3.connect(tmp_path / "rekos_cases" / "case-maigret-runtime-failure" / "rekos.db") as connection:
        row = connection.execute(
            "SELECT source, error FROM source_investigation_errors"
        ).fetchone()

    assert row[0] == "maigret_username"
    assert "Traceback" in row[1]
    assert "upstream details" in row[1]


def test_investigate_username_uses_multiple_sources_and_scores_confirmations(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setattr("rekos.adapters.sherlock.shutil.which", lambda tool: f"/usr/bin/{tool}")
    monkeypatch.setattr("rekos.adapters.maigret.shutil.which", lambda tool: f"/usr/bin/{tool}")
    monkeypatch.setattr("rekos.osint.shutil.which", lambda tool: f"/usr/bin/{tool}")

    def fake_run(cmd, check, capture_output, text, timeout):
        return SimpleNamespace(
            returncode=0,
            stdout="https://github.com/alice\n",
            stderr="",
        )

    def fake_wmn(self, case: str, target: str) -> str:
        return json.dumps(
            {
                "source": "wmn_username",
                "target": target,
                "results": [
                    {
                        "platform": "GitHub",
                        "url": "https://github.com/alice",
                        "status_code": 200,
                        "hit": True,
                        "error": "",
                    }
                ],
            }
        )

    monkeypatch.setattr("rekos.osint.subprocess.run", fake_run)
    monkeypatch.setattr(WmnUsernameAdapter, "run", fake_wmn)

    assert main(["new-case", "case-username-multisource"]) == 0
    assert main(["investigate", "username", "case-username-multisource", "alice"]) == 0

    output = capsys.readouterr().out
    assert "Discovered profiles: 1" in output

    assert main(["findings", "case-username-multisource", "--verbose"]) == 0
    findings_output = capsys.readouterr().out
    assert "Discovered URLs" in findings_output
    assert "3: maigret_username, sherlock_username, wmn_username" in findings_output

    case_folder = tmp_path / "rekos_cases" / "case-username-multisource"
    with sqlite3.connect(case_folder / "rekos.db") as connection:
        profile_count = connection.execute(
            "SELECT COUNT(*) FROM investigation_profiles"
        ).fetchone()[0]
        adapter_sources = [
            row[0]
            for row in connection.execute(
                "SELECT source FROM adapter_results ORDER BY source"
            ).fetchall()
        ]
        finding_rows = connection.execute(
            """
            SELECT source, quality_score, quality_reason
            FROM normalized_findings
            WHERE value = 'https://github.com/alice'
            ORDER BY source
            """
        ).fetchall()
        source_summary = connection.execute(
            "SELECT source_count, result_count, skipped_count, failed_count FROM source_investigations"
        ).fetchone()

    assert profile_count == 1
    assert adapter_sources == ["maigret_username", "sherlock_username", "wmn_username"]
    assert source_summary == (3, 1, 0, 0)
    assert {row[0] for row in finding_rows} == {
        "maigret_username",
        "sherlock_username",
        "wmn_username",
    }
    assert all(row[1] >= 95 for row in finding_rows)
    assert all("does not claim identity ownership" in row[2] for row in finding_rows)
    assert all("same URL confirmed by 3 source(s)" in row[2] for row in finding_rows)


def test_investigate_username_missing_sherlock(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setattr("rekos.adapters.sherlock.shutil.which", lambda _tool: None)

    assert main(["new-case", "case-no-sherlock"]) == 0
    assert main(["investigate", "username", "case-no-sherlock", "alice"]) == 1

    captured = capsys.readouterr()
    assert "Missing username investigation tool" in captured.err


def test_investigate_username_skips_unsafe_double_dot_variant(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setattr("rekos.adapters.sherlock.shutil.which", lambda tool: f"/usr/bin/{tool}")
    monkeypatch.setattr(MaigretAdapter, "run", _raise_missing_maigret)
    monkeypatch.setattr(WmnUsernameAdapter, "run", _empty_wmn)
    monkeypatch.setattr("rekos.osint.shutil.which", lambda tool: f"/usr/bin/{tool}")
    calls: list[str] = []

    def fake_run(cmd, check, capture_output, text, timeout):
        username = cmd[3]
        assert ".." not in username
        calls.append(username)
        return SimpleNamespace(
            returncode=0,
            stdout=f"https://profiles.example/{username}\n",
            stderr="",
        )

    monkeypatch.setattr("rekos.osint.subprocess.run", fake_run)

    assert main(["new-case", "case-unsafe-username"]) == 0
    assert (
        main(
            [
                "investigate",
                "username",
                "case-unsafe-username",
                "ciccio..gamer035",
            ]
        )
        == 0
    )

    captured = capsys.readouterr()
    assert "sherlock_username failed for ciccio..gamer035: invalid generated site URL / upstream tool error" in captured.out
    assert "Traceback" not in captured.out
    assert "Traceback" not in captured.err
    assert "LocationParseError" not in captured.out
    assert "LocationParseError" not in captured.err
    assert calls == ["cicciogamer035", "ciccio__gamer035"]

    case_folder = tmp_path / "rekos_cases" / "case-unsafe-username"
    with sqlite3.connect(case_folder / "rekos.db") as connection:
        username_entities = [
            row[0]
            for row in connection.execute(
                "SELECT value FROM entities WHERE entity_type = 'username' ORDER BY id"
            ).fetchall()
        ]
        adapter_targets = [
            row[0]
            for row in connection.execute(
                "SELECT target FROM adapter_results ORDER BY id"
            ).fetchall()
        ]
        investigation_row = connection.execute(
            """
            SELECT target_type, target, source_count, result_count,
                   skipped_count, failed_count
            FROM source_investigations
            """
        ).fetchone()
        error_row = connection.execute(
            "SELECT source, error FROM source_investigation_errors"
        ).fetchone()

    assert username_entities == [
        "ciccio..gamer035",
        "cicciogamer035",
        "ciccio__gamer035",
    ]
    assert adapter_targets == ["cicciogamer035", "ciccio__gamer035"]
    assert investigation_row == ("username", "ciccio..gamer035", 5, 2, 2, 0)
    assert error_row == (
        "sherlock_username",
        "sherlock_username failed for ciccio..gamer035: invalid generated site URL / upstream tool error",
    )

    assert main(["show-investigation", "case-unsafe-username"]) == 0
    show_output = capsys.readouterr().out
    assert "Username: ciccio..gamer035" in show_output
    assert "Skipped: 2" in show_output
    assert "sherlock_username failed for ciccio..gamer035" in show_output


def test_investigate_username_captures_sherlock_traceback_without_printing(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setattr("rekos.adapters.sherlock.shutil.which", lambda tool: f"/usr/bin/{tool}")
    monkeypatch.setattr(MaigretAdapter, "run", _raise_missing_maigret)
    monkeypatch.setattr(WmnUsernameAdapter, "run", _empty_wmn)
    monkeypatch.setattr("rekos.osint.shutil.which", lambda tool: f"/usr/bin/{tool}")

    def fake_run(cmd, check, capture_output, text, timeout):
        username = cmd[3]
        if username == "Alice.Smith":
            return SimpleNamespace(
                returncode=1,
                stdout="",
                stderr=(
                    "Traceback (most recent call last):\n"
                    "urllib3.exceptions.LocationParseError: Failed to parse URL\n"
                ),
            )
        return SimpleNamespace(
            returncode=0,
            stdout=f"https://profiles.example/{username}\n",
            stderr="",
        )

    monkeypatch.setattr("rekos.osint.subprocess.run", fake_run)

    assert main(["new-case", "case-traceback-username"]) == 0
    assert main(["investigate", "username", "case-traceback-username", "Alice.Smith"]) == 0

    captured = capsys.readouterr()
    assert "sherlock_username failed for Alice.Smith: invalid generated site URL / upstream tool error" in captured.out
    assert "Traceback" not in captured.out
    assert "Traceback" not in captured.err
    assert "LocationParseError" not in captured.out
    assert "LocationParseError" not in captured.err

    case_folder = tmp_path / "rekos_cases" / "case-traceback-username"
    with sqlite3.connect(case_folder / "rekos.db") as connection:
        investigation_row = connection.execute(
            """
            SELECT target_type, target, source_count, result_count,
                   skipped_count, failed_count
            FROM source_investigations
            """
        ).fetchone()
        error_row = connection.execute(
            "SELECT source, error FROM source_investigation_errors"
        ).fetchone()
        profile_count = connection.execute(
            "SELECT COUNT(*) FROM investigation_profiles"
        ).fetchone()[0]

    assert investigation_row == ("username", "Alice.Smith", 7, 3, 1, 1)
    assert error_row == (
        "sherlock_username",
        "sherlock_username failed for Alice.Smith: invalid generated site URL / upstream tool error",
    )
    assert profile_count == 3


def test_show_investigation_output(tmp_path: Path, monkeypatch, capsys) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setattr("rekos.adapters.sherlock.shutil.which", lambda tool: f"/usr/bin/{tool}")
    monkeypatch.setattr(MaigretAdapter, "run", _raise_missing_maigret)
    monkeypatch.setattr(WmnUsernameAdapter, "run", _empty_wmn)
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
    assert "Graph entities: 10" in output
    assert "Graph relationships: 23" in output
    assert "Findings: 4" in output
    assert "discovered_profile: https://profiles.example/Alice.Smith" in output
    assert "Timeline events:" in output


def test_investigate_domain_orchestrates_sources_and_continues_on_failure(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    registry = FakeSourceRegistry(
        {
            "rdap_domain": FakeSourceAdapter("rdap_domain"),
            "dns_domain": FakeSourceAdapter("dns_domain", fail=True),
            "web_domain": FakeSourceAdapter("web_domain"),
            "crtsh_domain": FakeSourceAdapter("crtsh_domain"),
        }
    )
    monkeypatch.setattr("rekos.investigation.default_registry", lambda: registry)

    assert main(["new-case", "case-domain-investigation"]) == 0
    assert main(["investigate", "domain", "case-domain-investigation", "Example.COM"]) == 0

    output = capsys.readouterr().out
    assert "Completed domain investigation" in output
    assert "example.com" in output
    assert "Records discovered: 3" in output
    assert "Warnings:" in output
    assert "dns_domain: temporary source failure" in output
    assert "Next steps:" in output
    assert "rekos findings case-domain-investigation" in output
    assert "rekos graph-summary case-domain-investigation" in output

    db_path = tmp_path / "rekos_cases" / "case-domain-investigation" / "rekos.db"
    with sqlite3.connect(db_path) as connection:
        investigation_row = connection.execute(
            """
            SELECT target_type, target, source_count, result_count,
                   skipped_count, failed_count
            FROM source_investigations
            """
        ).fetchone()
        error_row = connection.execute(
            "SELECT source, error FROM source_investigation_errors"
        ).fetchone()
        adapter_sources = [
            row[0]
            for row in connection.execute(
                "SELECT source FROM adapter_results ORDER BY id"
            ).fetchall()
        ]
        entity_values = [
            row[0]
            for row in connection.execute(
                "SELECT value FROM entities ORDER BY id"
            ).fetchall()
        ]
        relationship_count = connection.execute(
            "SELECT COUNT(*) FROM relationships"
        ).fetchone()[0]

    assert investigation_row == ("domain", "example.com", 3, 3, 0, 1)
    assert error_row == ("dns_domain", "temporary source failure")
    assert adapter_sources == ["rdap_domain", "web_domain", "crtsh_domain"]
    assert "example.com" in entity_values
    assert relationship_count == 3

    assert main(["show-investigation", "case-domain-investigation"]) == 0
    show_output = capsys.readouterr().out
    assert "Domain: example.com" in show_output
    assert "Sources run: 3" in show_output
    assert "Failed: 1" in show_output


def test_investigate_url_skips_missing_dependency_and_runs_available_source(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    registry = FakeSourceRegistry(
        {
            "http_snapshot": FakeSourceAdapter("http_snapshot", missing=("playwright",)),
            "wayback_url": FakeSourceAdapter("wayback_url"),
        }
    )
    monkeypatch.setattr("rekos.investigation.default_registry", lambda: registry)

    assert main(["new-case", "case-url-investigation"]) == 0
    assert main(
        [
            "investigate",
            "url",
            "case-url-investigation",
            "https://profiles.example/alice",
        ]
    ) == 0

    output = capsys.readouterr().out
    assert "Completed URL investigation" in output
    assert "Sources run: 1" in output
    assert "Results: 1" in output
    assert "Skipped: 1" in output
    assert "Failed: 0" in output
    assert "http_snapshot: Missing dependencies: playwright" in output

    db_path = tmp_path / "rekos_cases" / "case-url-investigation" / "rekos.db"
    with sqlite3.connect(db_path) as connection:
        investigation_row = connection.execute(
            """
            SELECT target_type, target, source_count, result_count,
                   skipped_count, failed_count
            FROM source_investigations
            """
        ).fetchone()
        adapter_source = connection.execute(
            "SELECT source FROM adapter_results"
        ).fetchone()[0]

    assert investigation_row == (
        "url",
        "https://profiles.example/alice",
        1,
        1,
        1,
        0,
    )
    assert adapter_source == "wayback_url"

    assert main(["show-investigation", "case-url-investigation"]) == 0
    show_output = capsys.readouterr().out
    assert "URL: https://profiles.example/alice" in show_output
    assert "Skipped: 1" in show_output


def test_report_renders_investigation_summary(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setattr("rekos.adapters.sherlock.shutil.which", lambda tool: f"/usr/bin/{tool}")
    monkeypatch.setattr(MaigretAdapter, "run", _raise_missing_maigret)
    monkeypatch.setattr(WmnUsernameAdapter, "run", _empty_wmn)
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
    def __init__(
        self,
        status: int = 200,
        body: bytes = b"<html>ok</html>",
        *,
        final_url: str = "",
        headers: dict[str, str] | None = None,
    ) -> None:
        self.status = status
        self.headers = headers or {"Content-Type": "text/html; charset=utf-8", "X-Test": "yes"}
        self._body = body
        self._final_url = final_url

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, traceback) -> None:
        return None

    def read(self, _limit: int) -> bytes:
        return self._body

    def geturl(self) -> str:
        return self._final_url


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


def test_investigate_domain_runs_rdap_and_dns_foundation(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    rdap_payload = {
        "objectClassName": "domain",
        "ldhName": "example.com",
        "links": [
            {"href": "https://rdap.verisign.com/com/v1/domain/example.com"},
            {"href": "https://icann.org/epp"},
        ],
    }
    dns_payloads = {
        "A": {"Status": 0, "Answer": [{"type": 1, "data": "93.184.216.34"}]},
        "AAAA": {"Status": 0, "Answer": [{"type": 28, "data": "2606:2800:220:1:248:1893:25c8:1946"}]},
        "MX": {"Status": 0, "Answer": [{"type": 15, "data": "10 mail.example.com."}]},
        "NS": {"Status": 0, "Answer": [{"type": 2, "data": "ns1.example.com."}]},
        "TXT": {
            "Status": 0,
            "Answer": [
                {"type": 16, "data": '"v=spf1 include:spf.protection.outlook.com -all"'},
                {"type": 16, "data": '"txt-two"'},
                {"type": 16, "data": '"txt-three"'},
                {"type": 16, "data": '"txt-four"'},
                {"type": 16, "data": '"txt-five"'},
                {"type": 16, "data": '"txt-six"'},
                {"type": 16, "data": '"txt-seven"'},
            ],
        },
    }

    def fake_urlopen(request, timeout):
        assert timeout == 15
        if request.full_url == "https://rdap.org/domain/example.com":
            return FakeHttpResponse(200, json.dumps(rdap_payload).encode("utf-8"))
        for record_type, payload in dns_payloads.items():
            if request.full_url == f"https://dns.google/resolve?name=example.com&type={record_type}":
                return FakeHttpResponse(200, json.dumps(payload).encode("utf-8"))
        if request.full_url == "https://example.com":
            return FakeHttpResponse(
                200,
                b"<html><head><title>Example Domain</title></head><body>ok</body></html>",
                final_url="https://example.com",
                headers={"Content-Type": "text/html; charset=utf-8", "Server": "example-server"},
            )
        if request.full_url == "http://example.com":
            return FakeHttpResponse(
                200,
                b"<html><head><title>Example Domain</title></head><body>ok</body></html>",
                final_url="https://example.com",
                headers={"Content-Type": "text/html; charset=utf-8", "Server": "example-server"},
            )
        if request.full_url.startswith("https://crt.sh/?"):
            return FakeHttpResponse(200, b"[]", headers={"Content-Type": "application/json"})
        raise AssertionError(f"unexpected URL: {request.full_url}")

    monkeypatch.setattr("rekos.adapters.web_osint.urlopen", fake_urlopen)
    monkeypatch.setattr(
        "rekos.adapters.web_osint._tls_certificate_summary",
        lambda domain: {
            "subject": f"www.{domain}",
            "issuer": "Example CA",
            "not_before": "Jan  1 00:00:00 2026 GMT",
            "not_after": "Jan  1 00:00:00 2027 GMT",
        },
    )

    assert main(["new-case", "case-domain-foundation"]) == 0
    assert main(["investigate", "domain", "case-domain-foundation", "Example.COM"]) == 0

    output = capsys.readouterr().out
    assert "Completed domain investigation" in output
    assert "example.com" in output
    assert "Records discovered: 20" in output
    assert "Sources run:" not in output
    assert "rekos findings case-domain-foundation" in output
    assert "rekos graph-summary case-domain-foundation" in output

    case_folder = tmp_path / "rekos_cases" / "case-domain-foundation"
    with sqlite3.connect(case_folder / "rekos.db") as connection:
        entity_counts = dict(
            connection.execute(
                "SELECT entity_type, COUNT(*) FROM entities GROUP BY entity_type"
            ).fetchall()
        )
        source_summary = connection.execute(
            "SELECT target_type, target, source_count, result_count, skipped_count, failed_count FROM source_investigations"
        ).fetchone()
        finding_rows = connection.execute(
            """
            SELECT finding_id, type, value, source, confidence
            FROM normalized_findings
            ORDER BY source, value
            """
        ).fetchall()
        dns_finding_id = connection.execute(
            """
            SELECT finding_id
            FROM normalized_findings
            WHERE type = 'dns_record'
              AND value = 'A example.com -> 93.184.216.34'
            """
        ).fetchone()[0]

    assert entity_counts["domain"] == 1
    assert entity_counts["ip"] == 2
    assert entity_counts["mx"] == 1
    assert entity_counts["nameserver"] == 1
    assert entity_counts["source"] == 3
    assert entity_counts["txt_record"] == 7
    assert entity_counts["mail_security"] == 1
    assert entity_counts["provider"] == 1
    assert entity_counts["web_endpoint"] == 2
    assert entity_counts["http_redirect"] == 1
    assert entity_counts["tls_certificate"] == 1
    assert source_summary == ("domain", "example.com", 4, 20, 0, 0)
    assert any(row[1:] == ("registration_record", "example.com", "rdap_domain", "high") for row in finding_rows)
    assert any(row[1:] == ("dns_record", "A example.com -> 93.184.216.34", "dns_domain", "high") for row in finding_rows)
    assert (
        "dns_record",
        "TXT example.com -> v=spf1 include:spf.protection.outlook.com -all",
        "dns_domain",
        "medium",
    ) in [row[1:] for row in finding_rows]
    assert any(row[1] == "mail_security" and row[3] == "dns_domain" for row in finding_rows)
    assert any(row[1] == "provider_hint" and "Microsoft 365" in row[2] for row in finding_rows)
    assert any(row[1] == "web_endpoint" and "Example Domain" in row[2] for row in finding_rows)
    assert any(row[1] == "http_redirect" and "http://example.com -> https://example.com" in row[2] for row in finding_rows)
    assert any(row[1] == "tls_certificate" and "Example CA" in row[2] for row in finding_rows)

    assert main(["graph-summary", "case-domain-foundation"]) == 0
    graph_output = capsys.readouterr().out
    assert "domain" in graph_output
    assert "ip" in graph_output
    assert "nameserver" in graph_output
    assert "mx" in graph_output
    assert "source" in graph_output
    assert "web_endpoint" in graph_output
    assert "tls_certificate" in graph_output
    assert "provider" in graph_output
    assert "Scope: targets, sources, DNS, web, TLS, providers, evidence links." in graph_output
    assert "Graph links" in graph_output
    assert "Graph links are internal relationships, not unique findings." in graph_output

    assert main(["findings", "case-domain-foundation"]) == 0
    findings_output = capsys.readouterr().out
    assert "Completed findings summary" in findings_output
    assert "registration_record example.com" in findings_output
    assert "dns_record" in findings_output
    assert "A example.com -> 93.184.216.34" in findings_output
    assert "AAAA example.com -> 2606:2800:220:1:248:1893:25c8:1946" in findings_output
    assert "MX example.com -> mail.example.com" in findings_output
    assert "NS example.com -> ns1.example.com" in findings_output
    assert "web_endpoint" in findings_output
    assert "tls_certificate" in findings_output
    assert "mail_security" in findings_output
    assert "provider_hint" in findings_output
    assert findings_output.count("TXT example.com ->") == 5
    assert "... and 2 more TXT records. Run rekos findings case-domain-foundation --verbose for details." in findings_output
    assert "https://rdap.verisign.com" not in findings_output
    assert "https://icann.org" not in findings_output

    assert main(["findings", "case-domain-foundation", "--verbose"]) == 0
    verbose_output = capsys.readouterr().out
    assert "Findings detail" in verbose_output
    assert "Registration" in verbose_output
    assert "DNS" in verbose_output
    assert "Mail security" in verbose_output
    assert "Web / HTTP" in verbose_output
    assert "TLS" in verbose_output
    assert "Provider hints are heuristic, low-confidence indicators unless corroborated." in verbose_output
    assert "Provider hints (heuristic / low confidence)" in verbose_output
    assert "Discovered URLs" in verbose_output
    assert "dns_record" in verbose_output
    assert "A example.com -> 93.184.216.34" in verbose_output
    assert "TXT example.com -> txt-six" in verbose_output
    assert "mail_security" in verbose_output
    assert "provider_hint" in verbose_output
    assert "Microsoft 365 provider hint" in verbose_output
    assert "web_endpoint" in verbose_output
    assert "tls_certificate" in verbose_output
    assert "https://rdap.verisign.com/com/v1/domain/example.com" in verbose_output
    assert "dns_domain" in verbose_output
    assert dns_finding_id not in verbose_output
    assert dns_finding_id[:8] in verbose_output

    assert main(["findings", "case-domain-foundation", "--verbose", "--show-uuids"]) == 0
    verbose_uuid_output = capsys.readouterr().out
    assert dns_finding_id in verbose_uuid_output


def test_investigate_domain_uses_rdap_it_fallback(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))

    def fake_urlopen(request, timeout):
        assert timeout == 15
        if request.full_url == "https://rdap.org/domain/r1spa.it":
            raise HTTPError(request.full_url, 404, "Not Found", hdrs=None, fp=None)
        if request.full_url == "https://rdap.nic.it/domain/r1spa.it":
            return FakeHttpResponse(
                200,
                json.dumps({"objectClassName": "domain", "ldhName": "r1spa.it"}).encode("utf-8"),
            )
        if request.full_url.startswith("https://dns.google/resolve?name=r1spa.it&type="):
            return FakeHttpResponse(200, json.dumps({"Status": 0, "Answer": []}).encode("utf-8"))
        if request.full_url in {"https://r1spa.it", "http://r1spa.it"}:
            return FakeHttpResponse(
                200,
                b"<html><head><title>R1 SPA</title></head></html>",
                final_url=request.full_url,
            )
        if request.full_url.startswith("https://crt.sh/?"):
            return FakeHttpResponse(200, b"[]", headers={"Content-Type": "application/json"})
        raise AssertionError(f"unexpected URL: {request.full_url}")

    monkeypatch.setattr("rekos.adapters.web_osint.urlopen", fake_urlopen)
    monkeypatch.setattr(
        "rekos.adapters.web_osint._tls_certificate_summary",
        lambda domain: {
            "subject": domain,
            "issuer": "IT Test CA",
            "not_before": "Jan  1 00:00:00 2026 GMT",
            "not_after": "Jan  1 00:00:00 2027 GMT",
        },
    )

    assert main(["new-case", "case-rdap-it-fallback"]) == 0
    assert main(["investigate", "domain", "case-rdap-it-fallback", "r1spa.it"]) == 0

    output = capsys.readouterr().out
    assert "Completed domain investigation r1spa.it" in output
    assert "Warnings:" not in output

    case_folder = tmp_path / "rekos_cases" / "case-rdap-it-fallback"
    with sqlite3.connect(case_folder / "rekos.db") as connection:
        rdap_urls = connection.execute(
            "SELECT url FROM adapter_results WHERE source = 'rdap_domain'"
        ).fetchall()
        source_summary = connection.execute(
            "SELECT source_count, failed_count FROM source_investigations"
        ).fetchone()

    assert ("https://rdap.nic.it/domain/r1spa.it",) in rdap_urls
    assert source_summary == (4, 0)


def test_investigate_domain_uses_whois_it_fallback(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))

    def fake_urlopen(request, timeout):
        assert timeout == 15
        if request.full_url in {
            "https://rdap.org/domain/r1spa.it",
            "https://rdap.nic.it/domain/r1spa.it",
        }:
            raise HTTPError(request.full_url, 404, "Not Found", hdrs=None, fp=None)
        if request.full_url == "https://data.iana.org/rdap/dns.json":
            return FakeHttpResponse(200, json.dumps({"services": []}).encode("utf-8"))
        if request.full_url.startswith("https://dns.google/resolve?name=r1spa.it&type="):
            return FakeHttpResponse(200, json.dumps({"Status": 0, "Answer": []}).encode("utf-8"))
        if request.full_url in {"https://r1spa.it", "http://r1spa.it"}:
            return FakeHttpResponse(
                200,
                b"<html><head><title>R1 SPA</title></head></html>",
                final_url=request.full_url,
            )
        if request.full_url.startswith("https://crt.sh/?"):
            return FakeHttpResponse(200, b"[]", headers={"Content-Type": "application/json"})
        raise AssertionError(f"unexpected URL: {request.full_url}")

    monkeypatch.setattr("rekos.adapters.web_osint.urlopen", fake_urlopen)
    monkeypatch.setattr(
        "rekos.adapters.web_osint._whois_lookup",
        lambda domain, server: f"Domain: {domain}\nStatus: ok\nRegistrar: Example Registrar\n",
    )
    monkeypatch.setattr(
        "rekos.adapters.web_osint._tls_certificate_summary",
        lambda domain: {
            "subject": domain,
            "issuer": "IT Test CA",
            "not_before": "Jan  1 00:00:00 2026 GMT",
            "not_after": "Jan  1 00:00:00 2027 GMT",
        },
    )

    assert main(["new-case", "case-whois-it-fallback"]) == 0
    assert main(["investigate", "domain", "case-whois-it-fallback", "r1spa.it"]) == 0

    output = capsys.readouterr().out
    assert "Completed domain investigation r1spa.it" in output
    assert "Warnings:" not in output

    case_folder = tmp_path / "rekos_cases" / "case-whois-it-fallback"
    with sqlite3.connect(case_folder / "rekos.db") as connection:
        rdap_urls = connection.execute(
            "SELECT url FROM adapter_results WHERE source = 'rdap_domain'"
        ).fetchall()

    assert ("whois://whois.nic.it/domain/r1spa.it",) in rdap_urls


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
        finding_rows = connection.execute(
            """
            SELECT type, value, source, confidence
            FROM normalized_findings
            ORDER BY id
            """
        ).fetchall()

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
    assert finding_rows == [
        ("certificate_record", "www.example.com", "crtsh_domain", "high"),
        ("discovered_domain", "www.example.com", "crtsh_domain", "medium"),
        ("certificate_record", "api.example.com", "crtsh_domain", "high"),
        ("discovered_domain", "api.example.com", "crtsh_domain", "medium"),
        ("certificate_record", "mail.example.com", "crtsh_domain", "high"),
        ("discovered_domain", "mail.example.com", "crtsh_domain", "medium"),
    ]

    assert main(["findings", "case-crtsh-source", "--verbose"]) == 0
    findings_output = capsys.readouterr().out
    assert "TLS" in findings_output
    assert "DNS" in findings_output
    assert "certificate_record" in findings_output
    assert "www.example.com" in findings_output
    assert "high" in findings_output
    assert "discovered_domain" in findings_output
    assert "api.example.com" in findings_output
    assert "medium" in findings_output
    assert "crtsh_domain" in findings_output


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


def test_findings_deduplicate_repeated_source_results(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    wayback_payload = [
        ["timestamp", "original", "statuscode", "mimetype"],
        ["20200101000000", "https://example.com/page", "200", "text/html"],
    ]

    def fake_urlopen(request, timeout):
        return FakeHttpResponse(200, json.dumps(wayback_payload).encode("utf-8"))

    monkeypatch.setattr("rekos.adapters.web_osint.urlopen", fake_urlopen)

    assert main(["new-case", "case-finding-dedupe"]) == 0
    assert main(["sources", "run", "case-finding-dedupe", "wayback_url", "example.com"]) == 0
    assert main(["sources", "run", "case-finding-dedupe", "wayback_url", "example.com"]) == 0
    capsys.readouterr()

    db_path = tmp_path / "rekos_cases" / "case-finding-dedupe" / "rekos.db"
    with sqlite3.connect(db_path) as connection:
        adapter_count = connection.execute(
            "SELECT COUNT(*) FROM adapter_results"
        ).fetchone()[0]
        finding_rows = connection.execute(
            """
            SELECT type, value, source, confidence
            FROM normalized_findings
            ORDER BY id
            """
        ).fetchall()

    assert adapter_count == 2
    assert finding_rows == [
        (
            "archive_record",
            "https://web.archive.org/web/20200101000000/https://example.com/page",
            "wayback_url",
            "medium",
        )
    ]


def test_findings_summary_dedupes_urls_and_normalizes_platform_labels(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    assert main(["new-case", "case-findings-summary"]) == 0

    store = CaseStore()
    store.add_adapter_results(
        "case-findings-summary",
        [
            AdapterResult(
                source="sherlock_username",
                target="alice",
                url="https://www.github.com/alice",
                platform="github",
                confidence="high",
                raw_reference="github exact",
            ),
            AdapterResult(
                source="wmn_username",
                target="alice",
                url="https://github.com/alice/",
                platform="github",
                confidence="medium",
                raw_reference="github no www trailing slash",
            ),
            AdapterResult(
                source="sherlock_username",
                target="alice",
                url="https://t.me/alice",
                platform="telegram",
                confidence="high",
                raw_reference="telegram",
            ),
            AdapterResult(
                source="sherlock_username",
                target="alice",
                url="https://scratch.mit.edu/users/alice",
                platform="scratch",
                confidence="high",
                raw_reference="scratch",
            ),
            AdapterResult(
                source="sherlock_username",
                target="alice",
                url="https://steamcommunity.com/id/alice",
                platform="steam",
                confidence="high",
                raw_reference="steam",
            ),
            AdapterResult(
                source="sherlock_username",
                target="alice",
                url="https://www.tiktok.com/@alice",
                platform="tiktok",
                confidence="high",
                raw_reference="tiktok",
            ),
            AdapterResult(
                source="sherlock_username",
                target="alice",
                url="https://www.youtube.com/@alice",
                platform="youtube",
                confidence="high",
                raw_reference="youtube",
            ),
        ],
    )
    capsys.readouterr()

    assert main(["findings", "case-findings-summary"]) == 0
    summary_output = capsys.readouterr().out
    github_lines = [
        line for line in summary_output.splitlines() if "github.com/alice" in line
    ]
    assert len(github_lines) == 1
    assert "- GitHub" in summary_output
    assert "- Telegram" in summary_output
    assert "- Scratch" in summary_output
    assert "- Steam" in summary_output
    assert "- TikTok" in summary_output
    assert "- YouTube" in summary_output
    assert "Confirming sources" not in summary_output

    assert main(["findings", "case-findings-summary", "--verbose"]) == 0
    verbose_output = capsys.readouterr().out
    assert "https://www.github.com/alice" in verbose_output
    assert "https://github.com/alice/" in verbose_output
    assert "Confirmed by" in verbose_output


def test_score_calculates_quality_and_labels(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    assert main(["new-case", "case-score"]) == 0
    assert main(["add-target", "case-score", "--type", "username", "--value", "alice"]) == 0

    store = CaseStore()
    profile_url = "https://profiles.example/alice"
    store.add_adapter_results(
        "case-score",
        [
            AdapterResult(
                source="sherlock_username",
                target="alice",
                url=profile_url,
                platform="profiles",
                confidence="high",
                raw_reference=profile_url,
            ),
            AdapterResult(
                source="maigret_username",
                target="alice",
                url=profile_url,
                platform="profiles",
                confidence="medium",
                raw_reference=profile_url,
            ),
            AdapterResult(
                source="sherlock_username",
                target="alice",
                url="https://profiles.example/bob",
                platform="profiles",
                confidence="low",
                raw_reference="https://profiles.example/bob",
            ),
        ],
    )
    exports = store.exports_folder("case-score")
    body_path = exports / "score-body.html"
    headers_path = exports / "score-headers.json"
    body_path.write_text("<html>alice</html>", encoding="utf-8")
    headers_path.write_text("{}", encoding="utf-8")
    store.add_url_snapshot("case-score", profile_url, 200, headers_path, body_path, None)
    username_entity = store.ensure_entity("case-score", "username", "alice", "score target")
    profile_entity = store.ensure_entity("case-score", "url", profile_url, "profile")
    store.relate_entities(
        "case-score",
        username_entity.entity_id,
        profile_entity.entity_id,
        "same_target",
        "medium",
        "correlation test",
    )
    capsys.readouterr()

    assert main(["score", "case-score"]) == 0

    output = capsys.readouterr().out
    assert "Finding Scores" in output
    assert "high" in output
    assert "low" in output
    db_path = tmp_path / "rekos_cases" / "case-score" / "rekos.db"
    with sqlite3.connect(db_path) as connection:
        rows = connection.execute(
            """
            SELECT value, source, quality_score, quality_reason
            FROM normalized_findings
            ORDER BY source, value
            """
        ).fetchall()

    profile_scores = [
        row
        for row in rows
        if row[0] == profile_url and row[1] in {"sherlock_username", "maigret_username"}
    ]
    weak_score = next(row for row in rows if row[0] == "https://profiles.example/bob")
    assert all(row[2] >= 75 for row in profile_scores)
    assert "normalized username match" in profile_scores[0][3]
    assert "duplicate confirmation across sources" in profile_scores[0][3]
    assert "local evidence artifact present" in profile_scores[0][3]
    assert weak_score[2] < 45
    assert "low quality label" in weak_score[3]
    assert "does not claim identity ownership" in profile_scores[0][3]

    assert main(["findings", "case-score", "--verbose"]) == 0
    findings_output = capsys.readouterr().out
    assert "Quality" in findings_output
    assert "Reason" in findings_output
    assert "Reason:" not in findings_output


def test_discovered_profile_quality_scores_username_match_strength(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    assert main(["new-case", "case-profile-quality"]) == 0

    store = CaseStore()
    store.add_adapter_results(
        "case-profile-quality",
        [
            AdapterResult(
                source="sherlock_username",
                target="Alice.Smith",
                url="https://profiles.example/Alice.Smith",
                platform="profiles",
                confidence="high",
                raw_reference="https://profiles.example/Alice.Smith",
            ),
            AdapterResult(
                source="sherlock_username",
                target="alice.smith",
                url="https://profiles.example/alice.smith",
                platform="profiles",
                confidence="medium",
                raw_reference="https://profiles.example/alice.smith",
            ),
            AdapterResult(
                source="sherlock_username",
                target="AliceSmith",
                url="https://profiles.example/AliceSmith",
                platform="profiles",
                confidence="low",
                raw_reference="https://profiles.example/AliceSmith",
            ),
        ],
    )
    capsys.readouterr()

    assert main(["findings", "case-profile-quality"]) == 0

    output = capsys.readouterr().out
    assert "quality 0/low" not in output
    assert "quality" in output
    db_path = tmp_path / "rekos_cases" / "case-profile-quality" / "rekos.db"
    with sqlite3.connect(db_path) as connection:
        rows = {
            row[0]: (row[1], row[2])
            for row in connection.execute(
                """
                SELECT value, quality_score, quality_reason
                FROM normalized_findings
                ORDER BY value
                """
            ).fetchall()
        }

    exact_score, exact_reason = rows["https://profiles.example/Alice.Smith"]
    normalized_score, normalized_reason = rows["https://profiles.example/alice.smith"]
    weak_score, weak_reason = rows["https://profiles.example/AliceSmith"]

    assert exact_score >= 80
    assert "exact username match in discovered profile URL" in exact_reason
    assert "does not claim identity ownership" in exact_reason
    assert normalized_score >= 60
    assert quality_label(normalized_score) == "medium"
    assert "normalized username match in discovered profile URL" in normalized_reason
    assert weak_score < 45
    assert quality_label(weak_score) == "low"
    assert "weak username variant match" in weak_reason


def test_wmn_only_template_hit_is_not_high_by_default(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    assert main(["new-case", "case-wmn-score"]) == 0

    store = CaseStore()
    store.add_adapter_results(
        "case-wmn-score",
        [
            AdapterResult(
                source="wmn_username",
                target="alice",
                url="https://github.com/alice",
                platform="github",
                confidence="medium",
                raw_reference="HTTP status: 200",
            )
        ],
    )
    capsys.readouterr()

    assert main(["score", "case-wmn-score"]) == 0

    with sqlite3.connect(tmp_path / "rekos_cases" / "case-wmn-score" / "rekos.db") as connection:
        score, reason = connection.execute(
            "SELECT quality_score, quality_reason FROM normalized_findings"
        ).fetchone()

    assert score < 75
    assert quality_label(score) in {"low", "medium"}
    assert "exact username match" not in reason
    assert "does not claim identity ownership" in reason


def test_sherlock_and_wmn_same_url_boosts_quality(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    assert main(["new-case", "case-wmn-confirmation"]) == 0

    store = CaseStore()
    profile_url = "https://github.com/alice"
    store.add_adapter_results(
        "case-wmn-confirmation",
        [
            AdapterResult(
                source="sherlock_username",
                target="alice",
                url=profile_url,
                platform="github",
                confidence="high",
                raw_reference=profile_url,
            ),
            AdapterResult(
                source="wmn_username",
                target="alice",
                url=profile_url,
                platform="github",
                confidence="medium",
                raw_reference="HTTP status: 200",
            ),
        ],
    )
    capsys.readouterr()

    assert main(["score", "case-wmn-confirmation"]) == 0

    with sqlite3.connect(tmp_path / "rekos_cases" / "case-wmn-confirmation" / "rekos.db") as connection:
        rows = connection.execute(
            """
            SELECT source, quality_score, quality_reason
            FROM normalized_findings
            ORDER BY source
            """
        ).fetchall()

    assert {row[0] for row in rows} == {"sherlock_username", "wmn_username"}
    assert all(row[1] >= 90 for row in rows)
    assert all("same URL confirmed by 2 source(s)" in row[2] for row in rows)
    assert all("does not claim identity ownership" in row[2] for row in rows)


def test_ambiguous_wmn_response_stays_low_or_medium(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))

    def fake_urlopen(request, timeout):
        return FakeHttpResponse(302, b"")

    monkeypatch.setattr("rekos.adapters.wmn.urlopen", fake_urlopen)

    assert main(["new-case", "case-wmn-ambiguous"]) == 0
    assert main(["sources", "run", "case-wmn-ambiguous", "wmn_username", "alice"]) == 0
    capsys.readouterr()
    assert main(["score", "case-wmn-ambiguous"]) == 0

    with sqlite3.connect(tmp_path / "rekos_cases" / "case-wmn-ambiguous" / "rekos.db") as connection:
        scores = [
            row[0]
            for row in connection.execute(
                "SELECT quality_score FROM normalized_findings"
            ).fetchall()
        ]

    assert scores
    assert all(quality_label(score) in {"low", "medium"} for score in scores)


def test_ambiguous_instagram_response_does_not_create_high_confidence(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))

    def fake_urlopen(request, timeout):
        status = 302 if "instagram.com" in request.full_url else 404
        return FakeHttpResponse(status, b"")

    monkeypatch.setattr("rekos.adapters.wmn.urlopen", fake_urlopen)

    assert main(["new-case", "case-instagram-ambiguous"]) == 0
    assert main(["sources", "run", "case-instagram-ambiguous", "wmn_username", "alice"]) == 0

    case_folder = tmp_path / "rekos_cases" / "case-instagram-ambiguous"
    source_output = "\n".join(
        path.read_text(encoding="utf-8")
        for path in (case_folder / "exports" / "sources").glob("*wmn_username-alice.txt")
    )
    assert "https://www.instagram.com/alice/" in source_output
    assert "ambiguous Instagram redirect" in source_output

    with sqlite3.connect(case_folder / "rekos.db") as connection:
        rows = connection.execute(
            """
            SELECT confidence, quality_score
            FROM normalized_findings
            WHERE value = 'https://www.instagram.com/alice/'
            """
        ).fetchall()

    assert rows == []
    capsys.readouterr()


def test_blocked_or_rate_limited_instagram_response_is_not_high(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))

    def fake_urlopen(request, timeout):
        status = 429 if "instagram.com" in request.full_url else 404
        return FakeHttpResponse(status, b"")

    monkeypatch.setattr("rekos.adapters.wmn.urlopen", fake_urlopen)

    assert main(["new-case", "case-instagram-blocked"]) == 0
    assert main(["sources", "run", "case-instagram-blocked", "wmn_username", "alice"]) == 0

    case_folder = tmp_path / "rekos_cases" / "case-instagram-blocked"
    source_output = "\n".join(
        path.read_text(encoding="utf-8")
        for path in (case_folder / "exports" / "sources").glob("*wmn_username-alice.txt")
    )
    assert "Instagram blocked or rate-limited passive request" in source_output

    with sqlite3.connect(case_folder / "rekos.db") as connection:
        rows = connection.execute(
            """
            SELECT confidence, quality_score
            FROM normalized_findings
            WHERE value = 'https://www.instagram.com/alice/'
            """
        ).fetchall()

    assert rows == []
    capsys.readouterr()


def test_cross_source_instagram_confirmation_boosts_score(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    assert main(["new-case", "case-instagram-confirmed"]) == 0

    store = CaseStore()
    profile_url = "https://www.instagram.com/alice/"
    store.add_adapter_results(
        "case-instagram-confirmed",
        [
            AdapterResult(
                source="sherlock_username",
                target="alice",
                url=profile_url,
                platform="instagram",
                confidence="high",
                raw_reference=profile_url,
            ),
            AdapterResult(
                source="wmn_username",
                target="alice",
                url=profile_url,
                platform="instagram",
                confidence="low",
                raw_reference=(
                    "HTTP status: 200; warning: Instagram HTTP 200 template hit; "
                    "low confidence unless cross-source confirmed"
                ),
            ),
        ],
    )
    capsys.readouterr()

    assert main(["score", "case-instagram-confirmed"]) == 0

    with sqlite3.connect(tmp_path / "rekos_cases" / "case-instagram-confirmed" / "rekos.db") as connection:
        rows = connection.execute(
            """
            SELECT source, quality_score, quality_reason
            FROM normalized_findings
            WHERE value = ?
            ORDER BY source
            """,
            (profile_url,),
        ).fetchall()

    assert {row[0] for row in rows} == {"sherlock_username", "wmn_username"}
    assert all(quality_label(row[1]) == "high" for row in rows)
    assert all("same URL confirmed by 2 source(s)" in row[2] for row in rows)
    assert all("does not claim identity ownership" in row[2] for row in rows)


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
    monkeypatch.setattr(WmnUsernameAdapter, "run", _empty_wmn)
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


def test_report_renders_findings_section(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    wayback_payload = [
        ["timestamp", "original", "statuscode", "mimetype"],
        ["20200101000000", "https://example.com/page", "200", "text/html"],
    ]

    def fake_urlopen(request, timeout):
        return FakeHttpResponse(200, json.dumps(wayback_payload).encode("utf-8"))

    monkeypatch.setattr("rekos.adapters.web_osint.urlopen", fake_urlopen)

    assert main(["new-case", "case-findings-report"]) == 0
    assert main(["sources", "run", "case-findings-report", "wayback_url", "example.com"]) == 0
    assert main(["score", "case-findings-report"]) == 0
    capsys.readouterr()

    assert main(["report", "case-findings-report"]) == 0

    output = capsys.readouterr().out
    assert "## Findings" in output
    assert "| `archive_record` |" in output
    assert "https://web.archive.org/web/20200101000000" in output
    assert "https://example.com/page" in output
    assert "| Type | Value | Confidence | Quality | Source | ID |" in output
    assert "| medium |" in output
    assert "wayback_url" in output
    assert "Full finding UUIDs, raw references, and scoring reasons remain available" in output


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
