"""Report rendering for case snapshots."""

from __future__ import annotations

from pathlib import Path

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
        f"- UUID: `{snapshot.case.uuid}`",
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
                    f"- Path: `{_display_path(file_hash.path, snapshot.case.folder)}`",
                    f"  - SHA-256: `{file_hash.sha256}`",
                    f"  - Size: {file_hash.size_bytes} bytes",
                    f"  - Added: {file_hash.added_at}",
                ]
            )
    else:
        lines.append("- None recorded")

    lines.extend(["", "## Evidence"])
    if snapshot.evidence:
        for evidence in snapshot.evidence:
            lines.extend(
                [
                    f"- ID: `{evidence.evidence_id}`",
                    f"  - Type: {evidence.evidence_type}",
                    f"  - Path: `{_display_path(evidence.path, snapshot.case.folder)}`",
                    f"  - SHA-256: `{evidence.sha256}`",
                    f"  - Created: {evidence.created_at}",
                ]
            )
            if evidence.source_url:
                lines.append(f"  - Source URL: {evidence.source_url}")
            if evidence.note:
                lines.append(f"  - Note: {evidence.note}")
    else:
        lines.append("- None recorded")

    lines.extend(["", "## Metadata Findings"])
    if snapshot.metadata:
        for metadata in snapshot.metadata:
            lines.extend(
                [
                    f"- File: `{_display_path(metadata.path, snapshot.case.folder)}`",
                    f"  - Tools: {metadata.tools}",
                    f"  - Export: `{_display_path(metadata.export_path, snapshot.case.folder)}`",
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
                    f"  - Export: `{_display_path(scan.export_path, snapshot.case.folder)}`",
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

    lines.extend(["", "## Timeline"])
    if snapshot.timeline:
        for event in snapshot.timeline:
            lines.append(f"- {event.created_at} `{event.event_type}` {event.summary}")
    else:
        lines.append("- None recorded")

    lines.extend(["", "## Validation"])
    if snapshot.validation:
        lines.extend(
            [
                f"- Status: {snapshot.validation.status}",
                f"- Checked: {snapshot.validation.checked_at}",
            ]
        )
        if snapshot.validation.warnings:
            lines.append("- Warnings:")
            for warning in snapshot.validation.warnings:
                lines.append(f"  - {warning}")
        else:
            lines.append("- Warnings: None")
    else:
        lines.append("- No validation recorded")

    lines.append("")
    return "\n".join(lines)


def _display_path(path_text: str, case_folder: str) -> str:
    path = Path(path_text)
    if not path.is_absolute():
        return path.as_posix()

    case_path = Path(case_folder)
    try:
        return path.relative_to(case_path).as_posix()
    except ValueError:
        return path.name
