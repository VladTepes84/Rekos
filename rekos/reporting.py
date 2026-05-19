"""Report rendering for case snapshots."""

from __future__ import annotations

from .errors import UnsupportedReportFormatError
from .models import CaseSnapshot


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
        for entity in snapshot.entities:
            lines.extend(
                [
                    f"- `{entity.entity_type}`: {entity.value}",
                    f"  - UUID: `{entity.entity_id}`",
                    f"  - Added: {entity.created_at}",
                ]
            )
            if entity.note:
                lines.append(f"  - Note: {entity.note}")
    else:
        lines.append("- None recorded")

    lines.extend(["", "## Relationships"])
    if snapshot.relationships:
        for relationship in snapshot.relationships:
            lines.extend(
                [
                    f"- `{relationship.relationship_type}` ({relationship.confidence})",
                    f"  - UUID: `{relationship.relationship_id}`",
                    f"  - From: `{relationship.source_entity_id}`",
                    f"  - To: `{relationship.target_entity_id}`",
                    f"  - Added: {relationship.created_at}",
                ]
            )
            if relationship.note:
                lines.append(f"  - Note: {relationship.note}")
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
        for entity in snapshot.graph_summary.most_connected:
            lines.append(
                f"  - `{entity.entity_id}` {entity.entity_type}: "
                f"{entity.value} ({entity.connection_count})"
            )
    else:
        lines.append("  - None recorded")

    lines.append("")
    return "\n".join(lines)
