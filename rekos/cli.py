"""Command-line interface for REKOS."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Sequence

from rich.console import Console
from rich.table import Table

from .adapters.registry import default_registry
from .errors import RekosError
from .exporting import export_case
from .hashfile import sha256_file
from .investigation import investigate_domain, investigate_url, investigate_username
from .osint import collect_metadata, scan_username
from .reporting import render_report
from .snapshots import snapshot_investigation, snapshot_url
from .storage import (
    ALLOWED_ENTITY_TYPES,
    ALLOWED_RELATIONSHIP_TYPES,
    CaseStore,
    quality_label,
)
from .usernames import username_variants


console = Console(width=240)
error_console = Console(stderr=True, width=240)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="rekos",
        description="Terminal-native passive OSINT CLI",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    new_case = subparsers.add_parser("new-case", help="Create a new local case")
    new_case.add_argument("name")

    add_target = subparsers.add_parser("add-target", help="Add a bounded case target")
    add_target.add_argument("case")
    add_target.add_argument("--type", required=True, dest="target_type")
    add_target.add_argument("--value", required=True)

    hash_file = subparsers.add_parser("hash-file", help="Hash a file and store the result in a case")
    hash_file.add_argument("case")
    hash_file.add_argument("file")

    metadata = subparsers.add_parser("metadata", help="Collect passive file metadata")
    metadata.add_argument("case")
    metadata.add_argument("file")

    username_scan = subparsers.add_parser("username-scan", help="Run a passive username scan")
    username_scan.add_argument("case")
    username_scan.add_argument("username")

    add_entity = subparsers.add_parser("add-entity", help="Add an entity to the local graph")
    add_entity.add_argument("case")
    add_entity.add_argument("--type", required=True, choices=sorted(ALLOWED_ENTITY_TYPES), dest="entity_type")
    add_entity.add_argument("--value", required=True)
    add_entity.add_argument("--note", default="")

    relate_entities = subparsers.add_parser("relate-entities", help="Create an entity relationship")
    relate_entities.add_argument("case")
    relate_entities.add_argument("--from", required=True, dest="source_entity_id")
    relate_entities.add_argument("--to", required=True, dest="target_entity_id")
    relate_entities.add_argument(
        "--type",
        required=True,
        choices=sorted(ALLOWED_RELATIONSHIP_TYPES),
        dest="relationship_type",
    )
    relate_entities.add_argument("--confidence", required=True)
    relate_entities.add_argument("--note", default="")

    list_entities = subparsers.add_parser("list-entities", help="List graph entities")
    list_entities.add_argument("case")

    list_targets = subparsers.add_parser("list-targets", help="List target-like entities")
    list_targets.add_argument("case")

    list_sources = subparsers.add_parser("list-sources", help="List local source runs")
    list_sources.add_argument("case")

    graph_summary = subparsers.add_parser("graph-summary", help="Summarize the entity graph")
    graph_summary.add_argument("case")

    search = subparsers.add_parser("search", help="Search local case records")
    search.add_argument("case")
    search.add_argument("query")
    search.add_argument(
        "--type",
        choices=["entity", "finding", "evidence", "timeline", "note", "relationship"],
        dest="result_type",
    )
    search.add_argument("--source")
    search.add_argument("--confidence", choices=["low", "medium", "high"])

    username_variants_parser = subparsers.add_parser("username-variants", help="Generate local username variants")
    username_variants_parser.add_argument("username")

    add_username_target = subparsers.add_parser(
        "add-username-target",
        help="Add a username target and graph variants",
    )
    add_username_target.add_argument("case")
    add_username_target.add_argument("username")

    investigate = subparsers.add_parser("investigate", help="Run a passive investigation workflow")
    investigate_subparsers = investigate.add_subparsers(dest="investigation_type", required=True)
    investigate_username_parser = investigate_subparsers.add_parser("username", help="Investigate a username")
    investigate_username_parser.add_argument("case")
    investigate_username_parser.add_argument("username")
    investigate_domain_parser = investigate_subparsers.add_parser("domain", help="Investigate a domain")
    investigate_domain_parser.add_argument("case")
    investigate_domain_parser.add_argument("domain")
    investigate_url_parser = investigate_subparsers.add_parser("url", help="Investigate a URL")
    investigate_url_parser.add_argument("case")
    investigate_url_parser.add_argument("url")

    show_investigation = subparsers.add_parser("show-investigation", help="Show investigation results")
    show_investigation.add_argument("case")

    findings = subparsers.add_parser("findings", help="List normalized findings")
    findings.add_argument("case")

    score = subparsers.add_parser("score", help="Score normalized findings")
    score.add_argument("case")

    snapshot_url_parser = subparsers.add_parser("snapshot-url", help="Capture a public URL snapshot")
    snapshot_url_parser.add_argument("case")
    snapshot_url_parser.add_argument("url")

    snapshot_investigation_parser = subparsers.add_parser(
        "snapshot-investigation",
        help="Snapshot discovered investigation profile URLs",
    )
    snapshot_investigation_parser.add_argument("case")

    sources = subparsers.add_parser("sources", help="Manage passive source adapters")
    sources_subparsers = sources.add_subparsers(dest="sources_command", required=True)
    sources_subparsers.add_parser("list", help="List passive source adapters")
    sources_subparsers.add_parser("check", help="Check source adapter dependencies")
    sources_run = sources_subparsers.add_parser("run", help="Run a passive source adapter")
    sources_run.add_argument("case")
    sources_run.add_argument("source")
    sources_run.add_argument("target")

    add_note = subparsers.add_parser("add-note", help="Add a note to a case")
    add_note.add_argument("case")
    add_note.add_argument("text")

    export_case_parser = subparsers.add_parser("export-case", help="Export a case ZIP archive")
    export_case_parser.add_argument("case")
    export_case_parser.add_argument("--output", required=True)

    report = subparsers.add_parser("report", help="Render a case report")
    report.add_argument("case")
    report.add_argument("--format", default="md", choices=["md"])

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    store = CaseStore()

    try:
        if args.command == "new-case":
            folder = store.create_case(args.name)
            console.print(f"[green]Created case[/green] {args.name} at {folder}")
            return 0

        if args.command == "add-target":
            target = store.add_target(args.case, args.target_type, args.value)
            console.print(f"[green]Added target[/green] {target.target_type}: {target.value}")
            return 0

        if args.command == "hash-file":
            source = Path(args.file).expanduser()
            if not source.is_file():
                raise FileNotFoundError(f"File not found: {source}")
            digest, size_bytes = sha256_file(source)
            file_hash = store.add_file_hash(args.case, source.resolve(), digest, size_bytes)
            console.print(f"[green]Hashed file[/green] {file_hash.path}")
            console.print(f"SHA-256: [bold]{file_hash.sha256}[/bold]")
            return 0

        if args.command == "metadata":
            tools, export_path = collect_metadata(args.case, Path(args.file), store)
            console.print(f"[green]Collected metadata[/green] with {', '.join(tools)}")
            console.print(f"Export: {export_path}")
            return 0

        if args.command == "username-scan":
            export_path = scan_username(args.case, args.username, store)
            console.print(f"[green]Completed username scan[/green] {args.username}")
            console.print(f"Export: {export_path}")
            return 0

        if args.command == "add-entity":
            entity = store.add_entity(args.case, args.entity_type, args.value, args.note)
            console.print(f"[green]Added entity[/green] {entity.entity_type}: {entity.value}")
            console.print(f"UUID: [bold]{entity.entity_id}[/bold]")
            return 0

        if args.command == "relate-entities":
            relationship = store.relate_entities(
                args.case,
                args.source_entity_id,
                args.target_entity_id,
                args.relationship_type,
                args.confidence,
                args.note,
            )
            console.print(
                f"[green]Added relationship[/green] {relationship.relationship_type} "
                f"({relationship.confidence})"
            )
            console.print(f"UUID: [bold]{relationship.relationship_id}[/bold]")
            return 0

        if args.command == "list-entities":
            entities = store.list_entities(args.case)
            if not entities:
                console.print("No entities recorded")
                return 0
            for entity in entities:
                note = f" - {entity.note}" if entity.note else ""
                console.print(
                    f"{entity.entity_id} {entity.entity_type}: {entity.value}{note}"
                )
            return 0

        if args.command == "list-targets":
            entities = store.target_like_entities(args.case)
            table = Table(title="Targets")
            table.add_column("Type")
            table.add_column("Value")
            table.add_column("UUID")
            table.add_column("Note")
            for entity in entities:
                table.add_row(entity.entity_type, entity.value, entity.entity_id, entity.note)
            console.print(table if entities else "No target-like entities recorded")
            return 0

        if args.command == "list-sources":
            runs = store.source_runs(args.case)
            table = Table(title="Source Runs")
            table.add_column("Source")
            table.add_column("Target")
            table.add_column("Status")
            table.add_column("Findings")
            table.add_column("Error")
            table.add_column("Created")
            for run in runs:
                table.add_row(
                    run.source,
                    run.target,
                    run.status,
                    str(run.findings_count),
                    run.error,
                    run.created_at,
                )
            console.print(table if runs else "No source runs recorded")
            return 0

        if args.command == "search":
            results = store.search(
                args.case,
                args.query,
                result_type=args.result_type,
                source=args.source,
                confidence=args.confidence,
            )
            table = Table(title="Search Results")
            table.add_column("Type")
            table.add_column("Subtype")
            table.add_column("Value")
            table.add_column("Source")
            table.add_column("Confidence")
            table.add_column("Context")
            table.add_column("Created")
            for result in results:
                table.add_row(
                    result.result_type,
                    result.subtype,
                    result.value,
                    result.source,
                    result.confidence,
                    result.context,
                    result.created_at,
                )
            console.print(table if results else "No results found")
            return 0

        if args.command == "graph-summary":
            summary = store.graph_summary(args.case)
            console.print(f"Total entities: {summary.total_entities}")
            console.print(f"Total relationships: {summary.total_relationships}")
            console.print("Entity type counts:")
            if summary.entity_type_counts:
                for entity_type, count in summary.entity_type_counts.items():
                    console.print(f"- {entity_type}: {count}")
            else:
                console.print("- None recorded")
            console.print("Most connected entities:")
            if summary.most_connected:
                for entity in summary.most_connected:
                    console.print(
                        f"- {entity.entity_id} {entity.entity_type}: "
                        f"{entity.value} ({entity.connection_count})"
                    )
            else:
                console.print("- None recorded")
            return 0

        if args.command == "username-variants":
            for variant in username_variants(args.username):
                if variant.confidence:
                    console.print(f"{variant.value} ({variant.confidence})")
                else:
                    console.print(variant.value)
            return 0

        if args.command == "add-username-target":
            original, variants = store.add_username_target(args.case, args.username)
            console.print(f"[green]Added username target[/green] {original.value}")
            console.print(f"Original UUID: [bold]{original.entity_id}[/bold]")
            console.print(f"Variants: {len(variants)}")
            return 0

        if args.command == "investigate" and args.investigation_type == "username":
            result = investigate_username(args.case, args.username, store)
            console.print(f"[green]Completed username investigation[/green] {result.username}")
            console.print(f"Variants: {len(result.variants)}")
            console.print(f"Discovered profiles: {len(result.profiles)}")
            for failure in result.failures:
                console.print(f"[yellow]Warning:[/yellow] {failure.error}")
            return 0

        if args.command == "investigate" and args.investigation_type == "domain":
            result = investigate_domain(args.case, args.domain, store)
            console.print(f"[green]Completed domain investigation[/green] {result.target}")
            console.print(f"Sources run: {result.sources_run}")
            console.print(f"Results: {result.results}")
            console.print(f"Skipped: {result.skipped}")
            console.print(f"Failed: {result.failed}")
            for failure in result.failures:
                console.print(f"- {failure.source}: {failure.error}")
            return 0

        if args.command == "investigate" and args.investigation_type == "url":
            result = investigate_url(args.case, args.url, store)
            console.print(f"[green]Completed URL investigation[/green] {result.target}")
            console.print(f"Sources run: {result.sources_run}")
            console.print(f"Results: {result.results}")
            console.print(f"Skipped: {result.skipped}")
            console.print(f"Failed: {result.failed}")
            for failure in result.failures:
                console.print(f"- {failure.source}: {failure.error}")
            return 0

        if args.command == "show-investigation":
            investigations = store.investigations(args.case)
            source_investigations = store.source_investigations(args.case)
            if not investigations and not source_investigations:
                console.print("No investigations recorded")
            for investigation in investigations:
                console.print(f"Username: {investigation.username}")
                console.print(f"Variants: {investigation.variant_count}")
                console.print(f"Discovered profiles: {investigation.profile_count}")
                if investigation.profiles:
                    for profile in investigation.profiles:
                        console.print(
                            f"- {profile.profile_url} "
                            f"({profile.confidence}) from {profile.source_username}"
                        )
                else:
                    console.print("- No profiles discovered")
            for investigation in source_investigations:
                label = "URL" if investigation.target_type == "url" else investigation.target_type.title()
                console.print(f"{label}: {investigation.target}")
                console.print(f"Sources run: {investigation.source_count}")
                console.print(f"Results: {investigation.result_count}")
                console.print(f"Skipped: {investigation.skipped_count}")
                console.print(f"Failed: {investigation.failed_count}")
                for error in investigation.errors:
                    console.print(f"- {error.source}: {error.error}")
            summary = store.graph_summary(args.case)
            console.print(f"Graph entities: {summary.total_entities}")
            console.print(f"Graph relationships: {summary.total_relationships}")
            findings = store.findings(args.case)
            console.print(f"Findings: {len(findings)}")
            for finding in findings[-10:]:
                console.print(
                    f"- {finding.finding_type}: {finding.value} "
                    f"({finding.confidence}) from {finding.source}; "
                    f"quality {finding.quality_score}/{quality_label(finding.quality_score)}"
                )
            timeline = store.snapshot(args.case).timeline
            console.print(f"Timeline events: {len(timeline)}")
            for event in timeline[-5:]:
                console.print(f"- {event.event_type}: {event.summary}")
            return 0

        if args.command == "findings":
            findings = store.findings(args.case, refresh_scores=True)
            if not findings:
                console.print("No findings recorded")
                return 0
            for finding in findings:
                console.print(
                    f"{finding.finding_id} {finding.finding_type}: {finding.value} "
                    f"({finding.confidence}) from {finding.source}; "
                    f"quality {finding.quality_score}/{quality_label(finding.quality_score)}"
                )
                console.print(
                    f"  Confirming sources ({finding.confirming_sources_count}): "
                    f"{finding.confirming_sources}"
                )
                if finding.quality_reason:
                    console.print(f"  Reason: {finding.quality_reason}")
            return 0

        if args.command == "score":
            findings = store.score_findings(args.case)
            if not findings:
                console.print("No findings to score")
                return 0
            table = Table(title="Finding Scores")
            table.add_column("Type")
            table.add_column("Value")
            table.add_column("Source")
            table.add_column("Score")
            table.add_column("Label")
            table.add_column("Reason")
            for finding in findings:
                table.add_row(
                    finding.finding_type,
                    finding.value,
                    finding.source,
                    str(finding.quality_score),
                    quality_label(finding.quality_score),
                    finding.quality_reason,
                )
            console.print(table)
            return 0

        if args.command == "snapshot-url":
            result = snapshot_url(args.case, args.url, store)
            if result.skipped:
                console.print(f"[yellow]Skipped recent snapshot[/yellow] {result.url}")
                return 0
            console.print(f"[green]Captured snapshot[/green] {result.url}")
            console.print(f"Body: {result.body_path}")
            console.print(f"Headers: {result.headers_path}")
            if result.screenshot_path:
                console.print(f"Screenshot: {result.screenshot_path}")
            else:
                console.print("Screenshot: not captured")
            return 0

        if args.command == "snapshot-investigation":
            result = snapshot_investigation(args.case, store)
            console.print(f"Captured: {result.captured}")
            console.print(f"Skipped: {result.skipped}")
            console.print(f"Failed: {result.failed}")
            for error in result.errors:
                console.print(f"- {error}")
            return 0

        if args.command == "sources":
            registry = default_registry()
            if args.sources_command == "list":
                for adapter in registry.list():
                    target_types = ", ".join(adapter.supported_target_types)
                    console.print(f"{adapter.name}: {adapter.description}")
                    console.print(f"  Targets: {target_types}")
                    console.print(f"  Passive only: {adapter.passive_only}")
                return 0

            if args.sources_command == "check":
                for adapter in registry.list():
                    console.print(f"{adapter.name}:")
                    dependencies = adapter.dependency_status()
                    if not dependencies:
                        console.print("  Dependencies: none")
                        continue
                    for dependency, available in dependencies.items():
                        status = "available" if available else "missing"
                        console.print(f"  {dependency}: {status}")
                        if not available and dependency == "maigret":
                            console.print("    Install hint: pipx inject rekos maigret")
                            console.print("    Or install REKOS with [full]", markup=False)
                return 0

            if args.sources_command == "run":
                adapter = registry.get(args.source)
                if not adapter.passive_only:
                    raise ValueError(f"Source is not passive-only: {adapter.name}")
                result = adapter.execute(args.case, args.target, store)
                console.print(f"[green]Ran source[/green] {result.source}")
                console.print(f"Target: {result.target}")
                console.print(f"Results: {len(result.results)}")
                if result.skipped:
                    console.print("Status: skipped recent duplicate")
                if result.artifacts:
                    console.print("Artifacts:")
                    for artifact in result.artifacts:
                        console.print(f"- {artifact}")
                return 0

        if args.command == "add-note":
            note = store.add_note(args.case, args.text)
            console.print(f"[green]Added note[/green] ({note.added_at})")
            return 0

        if args.command == "export-case":
            output_path = export_case(args.case, Path(args.output), store)
            console.print(f"[green]Exported case[/green] {args.case}")
            console.print(f"Archive: {output_path}")
            return 0

        if args.command == "report":
            report_text = render_report(store.snapshot(args.case), args.format)
            console.print(report_text, markup=False)
            return 0

    except (OSError, RekosError, ValueError) as exc:
        error_console.print(f"[red]Error:[/red] {exc}")
        return 1

    parser.error(f"Unhandled command: {args.command}")
    return 2


def console_main() -> None:
    sys.exit(main())


if __name__ == "__main__":
    console_main()
