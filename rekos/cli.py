"""Command-line interface for REKOS."""

from __future__ import annotations

import argparse
import sys
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Sequence
from urllib.parse import urlparse, urlunparse

from rich.console import Console
from rich.table import Table

from . import __version__
from .adapters.registry import default_registry
from .banner import render_banner
from .errors import RekosError
from .exporting import export_case
from .hashfile import sha256_file
from .investigation import (
    SourceInvestigationFailure,
    investigate_domain,
    investigate_url,
    investigate_username,
)
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
banner_console = Console(width=120)
error_console = Console(stderr=True, width=240)


@dataclass(frozen=True)
class _ProfileDisplayRow:
    platform: str
    url: str
    variant: str
    sources: str
    confidence: str
    reason: str


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="rekos",
        description="Terminal-native passive OSINT CLI",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("quickstart", help="Show installation and basic workflow")
    subparsers.add_parser("version", help="Show REKOS version")

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
    findings.add_argument("--verbose", action="store_true", help="Show full evidence details")
    findings.add_argument(
        "--show-uuids",
        action="store_true",
        help="Show full finding UUIDs in verbose output",
    )

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
    if argv is None:
        argv = sys.argv[1:]
    if not argv:
        argv = ["quickstart"]

    parser = build_parser()
    args = parser.parse_args(argv)
    store = CaseStore()

    try:
        if args.command == "quickstart":
            banner_console.print(render_banner())
            banner_console.print(f"Version: {__version__}")
            return 0

        if args.command == "version":
            console.print(f"rekos {__version__}")
            return 0

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
            _print_graph_summary(summary)
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
            _print_username_investigation_summary(args.case, result)
            return 0

        if args.command == "investigate" and args.investigation_type == "domain":
            result = investigate_domain(args.case, args.domain, store)
            _print_domain_investigation_summary(args.case, result, store)
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
            investigations = store.investigations(args.case)
            source_investigations = store.source_investigations(args.case)
            if args.verbose:
                _print_findings_verbose(
                    args.case,
                    findings,
                    investigations=investigations,
                    targets=_investigation_targets(source_investigations),
                    warnings=_source_warnings(source_investigations),
                    show_uuids=args.show_uuids,
                )
            else:
                _print_findings_summary(
                    args.case,
                    findings,
                    investigations=investigations,
                    targets=_investigation_targets(source_investigations),
                    warnings=_source_warnings(source_investigations),
                )
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
                            console.print("    Optional tool missing; REKOS continues without it.")
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


def _username_failure_warning(failure: SourceInvestigationFailure, username: str) -> str:
    if failure.error.startswith("Missing dependencies for "):
        prefix, _, detail = failure.error.partition(":")
        cleaned_detail = detail.strip().removeprefix("Missing username investigation tool: ").strip()
        return f"{prefix}: {cleaned_detail}"
    if failure.source == "maigret_username" and not failure.error.startswith("Missing dependencies"):
        return f"Maigret source failed for {username}; continuing with other sources."
    return failure.error


def _print_username_investigation_summary(case: str, result) -> None:
    console.print(f"[green]Completed username investigation[/green] {result.username}")
    console.print(f"Variants: {len(result.variants)}")
    console.print(f"Discovered profiles: {len(result.profiles)}")
    if result.profiles:
        console.print()
        console.print("Discovered profiles:")
        for profile in _sorted_profiles(result.profiles)[:10]:
            console.print(
                f"- {_profile_platform_label(profile.profile_url, profile.platform):<12} "
                f"{profile.profile_url} "
                f"[{profile.confidence}, {profile.source}, variant={profile.source_username}]",
                markup=False,
            )
        if len(result.profiles) > 10:
            console.print(f"- ... and {len(result.profiles) - 10} more profiles")

    console.print()
    console.print("Sources:")
    for line in _username_source_status_lines(result):
        console.print(f"- {line}", markup=False)

    if result.failures:
        console.print()
        console.print("Warnings:")
        for failure in result.failures:
            console.print(f"- {_username_failure_warning(failure, result.username)}")
    console.print()
    console.print("Next steps:")
    console.print(f"- rekos findings {case}")
    console.print(f"- rekos findings {case} --verbose")
    console.print(f"- rekos graph-summary {case}")
    console.print(f"- rekos export-case {case} --output {case}.zip")


def _print_domain_investigation_summary(case: str, result, store: CaseStore) -> None:
    findings = store.findings(case, refresh_scores=True)
    domain_findings = [
        finding
        for finding in findings
        if finding.value.lower().find(result.target.lower()) >= 0
        or finding.raw_reference.lower().find(result.target.lower()) >= 0
    ]
    breakdown = _domain_record_breakdown(domain_findings)
    console.print(f"[green]Completed domain investigation[/green] {result.target}")
    console.print(f"Records discovered: {result.results}")
    if breakdown:
        console.print()
        console.print("Record breakdown:")
        for label in ("A", "AAAA", "MX", "NS", "SPF", "DMARC", "DKIM", "TXT", "CNAME", "Certificates", "Subdomains", "Web / HTTP", "TLS"):
            count = breakdown.get(label, 0)
            if count:
                console.print(f"- {label:<12} {count}")

    preview = _domain_preview_findings(domain_findings)
    if preview:
        console.print()
        console.print("Key findings:")
        for finding in preview:
            console.print(f"- {_finding_summary_label(finding):<14} {_preview_value(finding.value)}", markup=False)
    if result.failures:
        console.print()
        console.print("Warnings:")
        for failure in result.failures:
            console.print(f"- {failure.source}: {failure.error}")
    console.print()
    console.print("Next steps:")
    console.print(f"- rekos findings {case}")
    console.print(f"- rekos findings {case} --verbose")
    console.print(f"- rekos graph-summary {case}")
    console.print(f"- rekos export-case {case} --output {case}.zip")


def _sorted_profiles(profiles) -> list:
    return sorted(
        profiles,
        key=lambda profile: (
            _profile_platform_label(profile.profile_url, profile.platform),
            profile.profile_url,
            profile.source,
            profile.source_username,
        ),
    )


def _username_source_status_lines(result) -> list[str]:
    profile_counts: dict[str, int] = {}
    for profile in result.profiles:
        profile_counts[profile.source] = profile_counts.get(profile.source, 0) + 1
    failure_by_source = {failure.source: failure for failure in result.failures}
    sources = sorted(set(profile_counts) | set(failure_by_source))
    lines: list[str] = []
    for source in sources:
        if source in profile_counts:
            label = _username_source_label(source)
            count = profile_counts[source]
            suffix = "profile" if count == 1 else "profiles"
            lines.append(f"{label}: ok ({count} {suffix})")
        else:
            warning = _username_failure_warning(failure_by_source[source], result.username)
            status = "missing dependency" if "Missing dependencies" in warning else "warning"
            lines.append(f"{source}: {status}")
    return lines


def _username_source_label(source: str) -> str:
    if source == "wmn_username":
        return "local/web username checks"
    return source


def _print_findings_summary(case: str, findings, *, investigations=(), targets=(), warnings=()) -> None:
    summary_findings, extra_txt_count = _summary_findings(findings)
    console.print(f"Case summary: {case}")
    console.print(f"Findings: {len(findings)}")
    _print_targets(targets)
    _print_username_findings_summary(summary_findings, investigations=investigations)

    key_source_findings = summary_findings
    if _profile_findings(summary_findings):
        key_source_findings = [
            finding
            for finding in summary_findings
            if finding.finding_type != "discovered_profile"
        ]
    key_findings = _key_findings(key_source_findings)
    if key_findings:
        console.print("")
        console.print("Key findings:")
        for finding in key_findings:
            console.print(f"- {_finding_summary_label(finding):<14} {_preview_value(finding.value)}", markup=False)

    if _has_domain_records(summary_findings):
        _print_domain_records(summary_findings, verbose=False)
    if extra_txt_count:
        console.print("")
        console.print(
            f"... and {extra_txt_count} more TXT records. "
            f"Run rekos findings {case} --verbose for details.",
            markup=False,
        )

    console.print("")
    console.print("Notes:")
    console.print("- Provider hints are heuristic and low-confidence unless corroborated.")
    _print_warnings(warnings)
    console.print("")
    console.print("Next steps:")
    console.print(f"- rekos findings {case} --verbose")
    console.print(f"- rekos graph-summary {case}")
    console.print(f"- rekos export-case {case} --output {case}.zip")


def _print_findings_verbose(case: str, findings, *, investigations=(), targets=(), warnings=(), show_uuids: bool = False) -> None:
    display_findings = _dedupe_profile_findings_for_display(findings)
    console.print(f"Case summary: {case}")
    console.print(f"Findings: {len(findings)}")
    _print_targets(targets)
    _print_username_findings_summary(
        display_findings,
        investigations=investigations,
        include_profiles=False,
    )
    console.print("")
    console.print("Key findings:")
    key_source_findings = display_findings
    if _profile_findings(display_findings):
        key_source_findings = [
            finding
            for finding in display_findings
            if finding.finding_type != "discovered_profile"
        ]
    key_findings = _key_findings(key_source_findings)
    if key_findings:
        for finding in key_findings:
            console.print(f"- {_finding_summary_label(finding):<14} {_preview_value(finding.value)}", markup=False)
    else:
        console.print("- None recorded")
    if _has_domain_records(display_findings):
        console.print("")
        console.print("Domain records")
        _print_domain_records(display_findings, verbose=True)
    _print_username_profiles_table(display_findings, investigations=investigations)
    console.print("")
    console.print("Notes:")
    console.print("Provider hints are heuristic, low-confidence indicators unless corroborated.")
    _print_warnings(warnings)
    console.print("")
    console.print("Detailed findings")
    detailed_findings = display_findings
    if _profile_findings(display_findings):
        detailed_findings = [
            finding
            for finding in display_findings
            if finding.finding_type != "discovered_profile"
        ]
    grouped = {category: [] for category in _finding_category_order()}
    for finding in detailed_findings:
        grouped.setdefault(_finding_category(finding), []).append(finding)

    for category in _finding_category_order():
        group = grouped.get(category, [])
        if not group:
            continue
        table = Table(title=_finding_category_title(category), show_header=True)
        table.add_column("ID", no_wrap=True)
        table.add_column("Type", no_wrap=True)
        table.add_column("Value", overflow="fold")
        table.add_column("Confidence", no_wrap=True)
        table.add_column("Quality", no_wrap=True)
        table.add_column("Source", no_wrap=True)
        table.add_column("Confirmed by")
        table.add_column("Reason", overflow="fold")
        for finding in sorted(
            group,
            key=lambda item: (
                -_confidence_rank(item.confidence),
                -item.quality_score,
                item.source,
                item.value,
            ),
        ):
            table.add_row(
                finding.finding_id if show_uuids else _short_id(finding.finding_id),
                finding.finding_type,
                _compact_finding_value(finding),
                finding.confidence,
                f"{finding.quality_score} {quality_label(finding.quality_score)}",
                finding.source,
                _compact_confirming_sources(finding),
                _compact_quality_reason(finding),
            )
        console.print(table)

    console.print("")
    console.print("Next steps:")
    console.print(f"- rekos graph-summary {case}")
    console.print(f"- rekos export-case {case} --output {case}.zip")


def _print_username_findings_summary(findings, *, investigations=(), include_profiles: bool = True) -> None:
    profile_findings = _profile_findings(findings)
    if not profile_findings and not investigations:
        return

    console.print("")
    console.print("Username investigations:")
    if investigations:
        for investigation in investigations:
            console.print(
                f"- {investigation.username}: {investigation.variant_count} variant(s), "
                f"{investigation.profile_count} discovered profile(s)"
            )
    else:
        console.print("- None recorded")

    if include_profiles and profile_findings:
        console.print("")
        console.print("Discovered profiles:")
        rows = _profile_display_rows(profile_findings, investigations=investigations)
        for row in rows[:12]:
            suffix = f", variant={row.variant}" if row.variant else ""
            console.print(
                f"- {row.platform:<12} {row.url} "
                f"[{row.confidence}, {row.sources}{suffix}]",
                markup=False,
            )
        if len(rows) > 12:
            console.print(f"- ... and {len(rows) - 12} more profiles")


def _print_username_profiles_table(findings, *, investigations=()) -> None:
    profile_findings = _profile_findings(findings)
    if not profile_findings:
        return
    table = Table(title="Discovered profiles", show_header=True)
    table.add_column("Platform", no_wrap=True)
    table.add_column("URL", overflow="fold")
    table.add_column("Username / variant", no_wrap=True)
    table.add_column("Sources", no_wrap=True)
    table.add_column("Confidence", no_wrap=True)
    table.add_column("Reason", overflow="fold")
    for row in _profile_display_rows(profile_findings, investigations=investigations):
        table.add_row(
            row.platform,
            row.url,
            row.variant,
            row.sources,
            row.confidence,
            row.reason,
        )
    console.print("")
    console.print(table)


def _profile_findings(findings) -> list:
    return [finding for finding in findings if finding.finding_type == "discovered_profile"]


def _profile_display_rows(findings, *, investigations=()) -> list[_ProfileDisplayRow]:
    profile_sources = _profile_source_usernames(investigations)
    rows: list[_ProfileDisplayRow] = []
    for finding in sorted(
        _dedupe_profile_findings_for_display(findings),
        key=_profile_finding_sort_key,
    ):
        if finding.finding_type != "discovered_profile":
            continue
        rows.append(
            _ProfileDisplayRow(
                platform=_profile_platform_label(finding.value, ""),
                url=finding.value,
                variant=_profile_variant_for_finding(finding, profile_sources),
                sources=finding.confirming_sources or finding.source,
                confidence=finding.confidence,
                reason=_compact_quality_reason(finding),
            )
        )
    return rows


def _dedupe_profile_findings_for_display(findings) -> list:
    deduped = []
    groups: dict[tuple[str, str], list] = {}
    for finding in findings:
        if finding.finding_type != "discovered_profile":
            deduped.append(finding)
            continue
        groups.setdefault(_profile_group_key(finding), []).append(finding)

    for group in groups.values():
        representative = max(group, key=_profile_representative_score)
        sources = _profile_group_sources(group)
        confidence = _profile_group_confidence(group, sources)
        quality_score = max(finding.quality_score for finding in group)
        quality_reason = representative.quality_reason
        if len(sources) > 1:
            quality_reason = "duplicate confirmation across sources"
        deduped.append(
            replace(
                representative,
                source=", ".join(sources),
                confidence=confidence,
                confirming_sources_count=len(sources),
                confirming_sources=", ".join(sources),
                quality_score=quality_score,
                quality_reason=quality_reason,
            )
        )
    return deduped


def _profile_group_key(finding) -> tuple[str, str]:
    return (
        _summary_value_key(finding.value),
        _profile_platform_label(finding.value, "").lower(),
    )


def _profile_representative_score(finding) -> tuple[int, int, int, int]:
    return (
        _confidence_rank(finding.confidence),
        finding.quality_score,
        finding.confirming_sources_count,
        -len(finding.value),
    )


def _profile_group_sources(findings) -> list[str]:
    sources: set[str] = set()
    for finding in findings:
        sources.add(finding.source)
        if finding.confirming_sources:
            sources.update(
                source.strip()
                for source in finding.confirming_sources.split(",")
                if source.strip()
            )
    return sorted(sources)


def _profile_group_confidence(findings, sources: list[str]) -> str:
    if len(sources) > 1:
        return "high"
    return max(
        (finding.confidence for finding in findings),
        key=_confidence_rank,
        default="low",
    )


def _profile_finding_sort_key(finding) -> tuple:
    return (
        _profile_platform_label(finding.value, ""),
        finding.value,
        finding.source,
        -_confidence_rank(finding.confidence),
    )


def _profile_source_usernames(investigations) -> dict[str, str]:
    values: dict[str, str] = {}
    for investigation in investigations:
        for profile in investigation.profiles:
            values.setdefault(profile.profile_url.lower(), profile.source_username)
            values.setdefault(_summary_value_key(profile.profile_url), profile.source_username)
    return values


def _profile_variant_for_finding(finding, profile_sources: dict[str, str]) -> str:
    return (
        profile_sources.get(finding.value.lower())
        or profile_sources.get(_summary_value_key(finding.value))
        or ""
    )


def _profile_platform_label(url: str, platform: str) -> str:
    cleaned_platform = platform.strip()
    if cleaned_platform and cleaned_platform.lower() not in {"unknown", "profiles"}:
        return _friendly_platform_label(cleaned_platform)
    host = urlparse(url).hostname or ""
    normalized_host = host.lower().removeprefix("www.")
    known_labels = {
        "github.com": "GitHub",
        "reddit.com": "Reddit",
        "instagram.com": "Instagram",
        "x.com": "X/Twitter",
        "twitter.com": "X/Twitter",
        "tiktok.com": "TikTok",
        "youtube.com": "YouTube",
        "twitch.tv": "Twitch",
        "pinterest.com": "Pinterest",
        "steamcommunity.com": "Steam",
        "medium.com": "Medium",
        "t.me": "Telegram",
        "scratch.mit.edu": "Scratch",
    }
    if normalized_host in known_labels:
        return known_labels[normalized_host]
    parts = [part for part in normalized_host.split(".") if part]
    if len(parts) >= 2:
        return parts[-2].title()
    if parts:
        return parts[0].title()
    return cleaned_platform or "Profile"


def _friendly_platform_label(value: str) -> str:
    normalized = value.strip().lower()
    labels = {
        "github": "GitHub",
        "reddit": "Reddit",
        "instagram": "Instagram",
        "twitter": "X/Twitter",
        "x": "X/Twitter",
        "tiktok": "TikTok",
        "youtube": "YouTube",
        "twitch": "Twitch",
        "pinterest": "Pinterest",
        "steam": "Steam",
        "medium": "Medium",
    }
    return labels.get(normalized, value.strip().title())


def _confidence_rank(confidence: str) -> int:
    return {"high": 3, "medium": 2, "low": 1}.get(confidence, 0)


def _investigation_targets(source_investigations) -> list[str]:
    seen: set[str] = set()
    targets: list[str] = []
    for investigation in source_investigations:
        label = f"{investigation.target_type}: {investigation.target}"
        if label in seen:
            continue
        seen.add(label)
        targets.append(label)
    return targets


def _source_warnings(source_investigations) -> list[str]:
    warnings: list[str] = []
    seen: set[str] = set()
    for investigation in source_investigations:
        for error in investigation.errors:
            warning = _clean_source_warning(error.source, error.error)
            if warning in seen:
                continue
            seen.add(warning)
            warnings.append(warning)
    return warnings


def _clean_source_warning(source: str, error: str) -> str:
    if source == "maigret_username" and error.startswith("Missing dependencies for maigret_username:"):
        cleaned = error.removeprefix("Missing dependencies for maigret_username:").strip()
        cleaned = cleaned.removeprefix("Missing username investigation tool:").strip()
        return f"Missing dependencies for maigret_username: {cleaned}"
    return f"{source}: {error}"


def _print_targets(targets) -> None:
    console.print("")
    console.print("Targets:")
    if targets:
        for target in targets:
            console.print(f"- {target}")
    else:
        console.print("- None recorded")


def _print_warnings(warnings) -> None:
    console.print("")
    console.print("Warnings:")
    if warnings:
        for warning in warnings:
            console.print(f"- {warning}", markup=False)
    else:
        console.print("- None")


def _key_findings(findings) -> list:
    findings = _dedupe_profile_findings_for_display(findings)
    priority = {
        "registration_record": 0,
        "mail_security": 1,
        "web_endpoint": 2,
        "http_redirect": 3,
        "tls_certificate": 4,
        "certificate_record": 5,
        "provider_hint": 6,
        "discovered_profile": 7,
        "discovered_url": 8,
    }
    selected = [
        finding
        for finding in findings
        if finding.finding_type in priority
    ]
    return sorted(
        selected,
        key=lambda finding: (
            priority[finding.finding_type],
            -_confidence_rank(finding.confidence),
            -finding.quality_score,
            finding.value,
        ),
    )[:8]


def _domain_preview_findings(findings) -> list:
    return _key_findings(findings)[:6]


def _domain_record_breakdown(findings) -> dict[str, int]:
    counts: dict[str, int] = {}
    for finding in findings:
        label = _domain_record_label(finding)
        if label:
            counts[label] = counts.get(label, 0) + 1
    return counts


def _print_domain_records(findings, *, verbose: bool) -> None:
    sections = [
        ("A", "A records"),
        ("AAAA", "AAAA records"),
        ("MX", "MX records"),
        ("NS", "NS records"),
        ("SPF", "SPF"),
        ("DMARC", "DMARC"),
        ("DKIM", "DKIM"),
        ("TXT", "Other TXT"),
        ("CNAME", "CNAME records"),
        ("Certificates", "Certificates"),
        ("Subdomains", "Certificate subdomains"),
        ("Web / HTTP", "Web / HTTP"),
        ("TLS", "TLS"),
    ]
    printed = False
    for label, title in sections:
        group = [finding for finding in findings if _domain_record_label(finding) == label]
        if not group:
            continue
        printed = True
        console.print("")
        console.print(f"{title}:")
        for finding in sorted(group, key=lambda item: (item.source, item.value)):
            value = _preview_value(finding.value, limit=180 if verbose else 120)
            if verbose:
                console.print(
                    f"- {value} [{finding.confidence}, {finding.source}, "
                    f"quality {finding.quality_score}/{quality_label(finding.quality_score)}]",
                    markup=False,
                )
            else:
                console.print(f"- {value}", markup=False)
    if not printed:
        console.print("")
        console.print("Domain records:")
        console.print("- None recorded")


def _has_domain_records(findings) -> bool:
    return any(_domain_record_label(finding) for finding in findings)


def _domain_record_label(finding) -> str:
    if finding.finding_type == "dns_record":
        record_type = _dns_record_type(finding.value)
        if record_type == "TXT":
            return _txt_record_label(finding.value)
        if record_type in {"A", "AAAA", "MX", "NS", "CNAME"}:
            return record_type
        return record_type
    if finding.finding_type == "mail_security":
        value = finding.value.upper()
        if "DMARC" in value:
            return "DMARC"
        if "DKIM" in value:
            return "DKIM"
        return "SPF"
    if finding.finding_type == "certificate_record":
        return "Certificates"
    if finding.finding_type == "discovered_domain":
        return "Subdomains"
    if finding.finding_type in {"web_endpoint", "http_redirect"}:
        return "Web / HTTP"
    if finding.finding_type == "tls_certificate":
        return "TLS"
    return ""


def _dns_record_type(value: str) -> str:
    parts = value.split(maxsplit=1)
    if not parts:
        return ""
    return parts[0].upper()


def _txt_record_label(value: str) -> str:
    normalized = value.lower()
    if "v=spf1" in normalized:
        return "SPF"
    if "v=dmarc1" in normalized or "_dmarc" in normalized:
        return "DMARC"
    if "v=dkim1" in normalized or "._domainkey" in normalized or "dkim" in normalized:
        return "DKIM"
    return "TXT"


def _preview_value(value: str, *, limit: int = 140) -> str:
    return _truncate_text(" ".join(value.strip().split()), limit)


def _finding_category_order() -> list[str]:
    return [
        "registration",
        "dns",
        "mail_security",
        "web_http",
        "tls",
        "provider_hints",
        "discovered_urls",
        "other",
    ]


def _finding_category(finding) -> str:
    finding_type = finding.finding_type
    if finding_type == "registration_record":
        return "registration"
    if finding_type in {"dns_record", "discovered_domain"}:
        return "dns"
    if finding_type == "mail_security":
        return "mail_security"
    if finding_type in {"web_endpoint", "http_redirect"}:
        return "web_http"
    if finding_type in {"tls_certificate", "certificate_record"}:
        return "tls"
    if finding_type == "provider_hint":
        return "provider_hints"
    if finding_type in {"discovered_url", "discovered_profile", "archive_record"}:
        return "discovered_urls"
    return "other"


def _finding_category_title(category: str) -> str:
    return {
        "registration": "Registration",
        "dns": "DNS",
        "mail_security": "Mail security",
        "web_http": "Web / HTTP",
        "tls": "TLS",
        "provider_hints": "Provider hints (heuristic / low confidence)",
        "discovered_urls": "Discovered URLs",
        "other": "Other",
    }[category]


def _short_id(value: str) -> str:
    return value[:8] if len(value) > 8 else value


def _compact_finding_value(finding) -> str:
    value = " ".join(finding.value.strip().split())
    if finding.finding_type == "provider_hint":
        value = f"heuristic indicator: {value}"
    return _truncate_text(value, 140)


def _compact_confirming_sources(finding) -> str:
    if finding.confirming_sources_count <= 1:
        return finding.source
    return _truncate_text(f"{finding.confirming_sources_count}: {finding.confirming_sources}", 90)


def _compact_quality_reason(finding) -> str:
    if not finding.quality_reason:
        return "not scored"
    parts = [
        part.strip()
        for part in finding.quality_reason.split(";")
        if part.strip()
        and "does not claim identity ownership" not in part
        and not part.strip().endswith("quality label")
    ]
    if finding.finding_type == "provider_hint":
        parts.insert(0, "heuristic indicator")
    return _truncate_text("; ".join(parts[:3]) if parts else "scored locally", 120)


def _truncate_text(value: str, limit: int) -> str:
    if len(value) <= limit:
        return value
    return f"{value[: limit - 3]}..."


def _dedupe_summary_findings(findings):
    selected = {}
    for finding in findings:
        key = (finding.finding_type, _summary_value_key(finding.value))
        current = selected.get(key)
        if current is None or _summary_sort_score(finding) > _summary_sort_score(current):
            selected[key] = finding
    return list(selected.values())


def _summary_findings(findings):
    summary_findings = []
    txt_count = 0
    extra_txt_count = 0
    for finding in _dedupe_summary_findings(findings):
        if _is_rdap_technical_url(finding):
            continue
        if _is_dns_txt_record(finding):
            txt_count += 1
            if txt_count > 5:
                extra_txt_count += 1
                continue
        summary_findings.append(finding)
    return summary_findings, extra_txt_count


def _is_dns_txt_record(finding) -> bool:
    return finding.finding_type == "dns_record" and finding.value.startswith("TXT ")


def _is_rdap_technical_url(finding) -> bool:
    return finding.finding_type == "discovered_url" and finding.source == "rdap_domain"


def _summary_sort_score(finding) -> tuple[int, int, int]:
    return (
        _confidence_rank(finding.confidence),
        finding.quality_score,
        finding.confirming_sources_count,
    )


def _summary_value_key(value: str) -> str:
    parsed = urlparse(value.strip())
    if parsed.scheme in {"http", "https"} and parsed.netloc:
        host = parsed.netloc.lower()
        if host.startswith("www."):
            host = host[4:]
        path = parsed.path.rstrip("/")
        return urlunparse(
            (
                parsed.scheme.lower(),
                host,
                path,
                "",
                parsed.query,
                "",
            )
        )
    return value.strip().lower()


def _finding_summary_label(finding) -> str:
    if finding.finding_type == "discovered_profile":
        host = urlparse(finding.value).hostname or ""
        normalized_host = host.lower().removeprefix("www.")
        known_labels = {
            "github.com": "GitHub",
            "tiktok.com": "TikTok",
            "youtube.com": "YouTube",
            "t.me": "Telegram",
            "scratch.mit.edu": "Scratch",
            "steamcommunity.com": "Steam",
        }
        if normalized_host in known_labels:
            return known_labels[normalized_host]
        parts = [part for part in normalized_host.split(".") if part]
        if len(parts) >= 2:
            return parts[-2].title()
        if parts:
            return parts[0].title()
    return finding.finding_type


def _print_graph_summary(summary) -> None:
    console.print("Graph overview")
    console.print(f"Entities: {summary.total_entities}")
    console.print(f"Relationships: {summary.total_relationships}")
    if summary.total_relationships == 0:
        console.print("No graph relationships available yet. Run findings --verbose to inspect collected records.")
        return
    console.print("Scope: targets, sources, DNS, web, TLS, providers, evidence links.")

    type_table = Table(title="Entity types", show_header=True)
    type_table.add_column("Type")
    type_table.add_column("Count", justify="right")
    if summary.entity_type_counts:
        for entity_type, count in summary.entity_type_counts.items():
            type_table.add_row(entity_type, str(count))
    else:
        type_table.add_row("None recorded", "0")
    console.print(type_table)

    connected_table = Table(title="Most connected", show_header=True)
    connected_table.add_column("Type")
    connected_table.add_column("Value")
    connected_table.add_column("Graph links", justify="right")
    if summary.most_connected:
        for entity in summary.most_connected:
            connected_table.add_row(
                entity.entity_type,
                entity.value,
                str(entity.connection_count),
            )
    else:
        connected_table.add_row("None recorded", "", "0")
    console.print(connected_table)
    console.print("Graph links are internal relationships, not unique findings.")


if __name__ == "__main__":
    console_main()
