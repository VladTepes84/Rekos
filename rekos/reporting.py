"""Report rendering for case snapshots."""

from __future__ import annotations

from .errors import UnsupportedReportFormatError
from .models import CaseSnapshot
from .storage import quality_label


def render_report(snapshot: CaseSnapshot, report_format: str) -> str:
    normalized_format = report_format.strip().lower()
    if normalized_format != "md":
        raise UnsupportedReportFormatError(f"Unsupported report format: {report_format}")
    return render_markdown(snapshot)


def render_markdown(snapshot: CaseSnapshot) -> str:
    lines: list[str] = [
        f"# REKOS Case Report: {snapshot.case.name}",
        "",
        "## Case",
        f"- Created: {snapshot.case.created_at}",
        "",
        "## Targets",
    ]

    if snapshot.targets:
        for target in snapshot.targets:
            lines.append(f"- `{target.target_type}`: {target.value} ({target.added_at})")
    else:
        lines.append("- None recorded")

    lines.extend(["", "## File Hashes"])
    if snapshot.file_hashes:
        for file_hash in snapshot.file_hashes:
            lines.extend(
                [
                    f"- Path: `{file_hash.path}`",
                    f"  - SHA-256: `{file_hash.sha256}`",
                    f"  - Size: {file_hash.size_bytes} bytes",
                    f"  - Added: {file_hash.added_at}",
                ]
            )
    else:
        lines.append("- None recorded")

    lines.extend(["", "## Metadata Findings"])
    if snapshot.metadata:
        for metadata in snapshot.metadata:
            lines.extend(
                [
                    f"- File: `{metadata.path}`",
                    f"  - Tools: {metadata.tools}",
                    f"  - Export: `{metadata.export_path}`",
                    f"  - Added: {metadata.added_at}",
                ]
            )
    else:
        lines.append("- None recorded")

    lines.extend(["", "## Username Scans"])
    if snapshot.username_scans:
        for scan in snapshot.username_scans:
            lines.extend(
                [
                    f"- Username: `{scan.username}`",
                    f"  - Export: `{scan.export_path}`",
                    f"  - Added: {scan.added_at}",
                ]
            )
    else:
        lines.append("- None recorded")

    lines.extend(["", "## Notes"])
    if snapshot.notes:
        for note in snapshot.notes:
            lines.append(f"- {note.text} ({note.added_at})")
    else:
        lines.append("- None recorded")

    lines.extend(["", "## Entities"])
    if snapshot.entities:
        lines.extend(["| Type | Value | ID | Note |", "| --- | --- | --- | --- |"])
        for entity in snapshot.entities:
            lines.append(
                "| "
                f"`{_escape_table(entity.entity_type)}` | "
                f"{_escape_table(entity.value)} | "
                f"`{_short_id(entity.entity_id)}` | "
                f"{_escape_table(entity.note or '')} |"
            )
    else:
        lines.append("- None recorded")

    lines.extend(["", "## Relationships"])
    if snapshot.relationships:
        entity_labels = {
            entity.entity_id: f"{entity.entity_type}:{_short_value(entity.value)}"
            for entity in snapshot.entities
        }
        lines.extend(
            [
                "| Type | Confidence | From | To | ID | Note |",
                "| --- | --- | --- | --- | --- | --- |",
            ]
        )
        for relationship in snapshot.relationships:
            lines.append(
                "| "
                f"`{_escape_table(relationship.relationship_type)}` | "
                f"{_escape_table(relationship.confidence)} | "
                f"{_escape_table(entity_labels.get(relationship.source_entity_id, _short_id(relationship.source_entity_id)))} | "
                f"{_escape_table(entity_labels.get(relationship.target_entity_id, _short_id(relationship.target_entity_id)))} | "
                f"`{_short_id(relationship.relationship_id)}` | "
                f"{_escape_table(relationship.note or '')} |"
            )
    else:
        lines.append("- None recorded")

    lines.extend(["", "## Graph Summary"])
    lines.extend(
        [
            f"- Total entities: {snapshot.graph_summary.total_entities}",
            f"- Total relationships: {snapshot.graph_summary.total_relationships}",
            "- Entity type counts:",
        ]
    )
    if snapshot.graph_summary.entity_type_counts:
        for entity_type, count in snapshot.graph_summary.entity_type_counts.items():
            lines.append(f"  - {entity_type}: {count}")
    else:
        lines.append("  - None recorded")
    lines.append("- Most connected entities:")
    if snapshot.graph_summary.most_connected:
        lines.extend(["", "| Type | Value | Graph links | ID |", "| --- | --- | --- | --- |"])
        for entity in snapshot.graph_summary.most_connected:
            lines.append(
                "| "
                f"`{_escape_table(entity.entity_type)}` | "
                f"{_escape_table(_short_value(entity.value, limit=120))} | "
                f"{entity.connection_count} | "
                f"`{_short_id(entity.entity_id)}` |"
            )
    else:
        lines.append("  - None recorded")

    lines.extend(["", "## Findings"])
    if snapshot.findings:
        lines.extend(
            [
                "| Type | Value | Confidence | Quality | Source | ID |",
                "| --- | --- | --- | --- | --- | --- |",
            ]
        )
        for finding in snapshot.findings:
            lines.append(
                "| "
                f"`{_escape_table(finding.finding_type)}` | "
                f"{_escape_table(_short_value(finding.value, limit=120))} | "
                f"{_escape_table(finding.confidence)} | "
                f"{finding.quality_score} ({quality_label(finding.quality_score)}) | "
                f"{_escape_table(finding.source)} | "
                f"`{_short_id(finding.finding_id)}` |"
            )
        lines.append("")
        lines.append("Full finding UUIDs, raw references, and scoring reasons remain available in the case database and exports.")
    else:
        lines.append("- None recorded")

    lines.extend(["", "## Investigations"])
    if snapshot.investigations:
        for investigation in snapshot.investigations:
            lines.extend(
                [
                    f"- Username: {investigation.username}",
                    f"  - Variants: {investigation.variant_count}",
                    f"  - Discovered profiles: {investigation.profile_count}",
                    f"  - Added: {investigation.created_at}",
                ]
            )
            if investigation.profiles:
                lines.append("  - Profiles:")
                for profile in investigation.profiles:
                    lines.append(
                        f"    - {profile.profile_url} "
                        f"({profile.confidence}, from {profile.source_username})"
                    )
            else:
                lines.append("  - Profiles: None recorded")
    else:
        lines.append("- None recorded")

    lines.extend(["", "## Snapshots"])
    if snapshot.snapshots:
        for snapshot_record in snapshot.snapshots:
            status = (
                str(snapshot_record.status_code)
                if snapshot_record.status_code is not None
                else "unknown"
            )
            lines.extend(
                [
                    f"- URL: {snapshot_record.url}",
                    f"  - Captured: {snapshot_record.captured_at}",
                    f"  - HTTP status: {status}",
                    f"  - Headers: `{snapshot_record.headers_path}`",
                    f"  - Body: `{snapshot_record.body_path}`",
                    f"  - Evidence: `{snapshot_record.evidence_id}`",
                ]
            )
            if snapshot_record.screenshot_path:
                lines.append(f"  - Screenshot: `{snapshot_record.screenshot_path}`")
    else:
        lines.append("- None recorded")

    lines.append("")
    return "\n".join(lines)


def _short_id(value: str) -> str:
    cleaned = value.strip()
    return cleaned[:8] if len(cleaned) > 8 else cleaned


def _short_value(value: str, *, limit: int = 80) -> str:
    cleaned = " ".join(value.strip().split())
    if len(cleaned) <= limit:
        return cleaned
    return f"{cleaned[: limit - 1]}..."


def _escape_table(value: str) -> str:
    return value.replace("|", "\\|").replace("\n", " ")
