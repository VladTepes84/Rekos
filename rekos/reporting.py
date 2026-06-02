"""Report rendering for case snapshots."""

from __future__ import annotations

from datetime import datetime, timezone

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
        "## Case metadata",
        f"- Created: {snapshot.case.created_at}",
        f"- Generated at: {datetime.now(timezone.utc).isoformat(timespec='seconds')}",
        "",
        "## Targets",
    ]

    if snapshot.targets:
        for target in snapshot.targets:
            lines.append(f"- `{target.target_type}`: {target.value} ({target.added_at})")
    else:
        lines.append("- None recorded")

    lines.extend(["", "## Executive summary"])
    lines.extend(_render_executive_summary(snapshot))

    lines.extend(["", "## Key findings"])
    lines.extend(_render_key_findings(snapshot.findings))

    lines.extend(["", "## Technical findings"])
    lines.extend(_render_technical_findings(snapshot.findings))

    lines.extend(["", "## Domain records grouped by type"])
    lines.extend(_render_domain_records(snapshot.findings))

    lines.extend(["", "## TXT / SPF / DMARC / DKIM"])
    lines.extend(_render_txt_sections(snapshot.findings))

    lines.extend(["", "## Warnings / source errors"])
    lines.extend(_render_source_warnings(snapshot))

    lines.extend(["", "## Evidence / local artifacts"])
    lines.extend(_render_evidence_artifacts(snapshot))

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

    lines.extend(["", "## Generated at"])
    lines.append(datetime.now(timezone.utc).isoformat(timespec="seconds"))
    lines.append("")
    return "\n".join(lines)


def _render_executive_summary(snapshot: CaseSnapshot) -> list[str]:
    warnings_count = sum(len(investigation.errors) for investigation in snapshot.source_investigations)
    return [
        f"- Findings: {len(snapshot.findings)}",
        f"- Entities: {snapshot.graph_summary.total_entities}",
        f"- Graph relationships: {snapshot.graph_summary.total_relationships}",
        f"- Source warnings: {warnings_count}",
    ]


def _render_key_findings(findings) -> list[str]:
    selected = sorted(
        [
            finding
            for finding in findings
            if finding.finding_type
            in {
                "registration_record",
                "mail_security",
                "web_endpoint",
                "http_redirect",
                "tls_certificate",
                "certificate_record",
                "provider_hint",
                "discovered_profile",
                "discovered_url",
            }
        ],
        key=lambda finding: (
            _key_priority(finding.finding_type),
            -_confidence_rank(finding.confidence),
            -finding.quality_score,
            finding.value,
        ),
    )[:10]
    if not selected:
        return ["- None recorded"]
    return [
        f"- **{finding.finding_type}** ({finding.confidence}, {finding.source}): "
        f"{_short_value(finding.value, limit=140)}"
        for finding in selected
    ]


def _render_technical_findings(findings) -> list[str]:
    if not findings:
        return ["- None recorded"]
    lines = [
        "| Type | Value | Confidence | Quality | Source | ID |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    for finding in sorted(
        findings,
        key=lambda item: (
            _key_priority(item.finding_type),
            _domain_record_label(item),
            item.source,
            item.value,
        ),
    ):
        lines.append(
            "| "
            f"`{_escape_table(finding.finding_type)}` | "
            f"{_escape_table(_short_value(finding.value, limit=140))} | "
            f"{_escape_table(finding.confidence)} | "
            f"{finding.quality_score} ({quality_label(finding.quality_score)}) | "
            f"{_escape_table(finding.source)} | "
            f"`{_short_id(finding.finding_id)}` |"
        )
    return lines


def _render_domain_records(findings) -> list[str]:
    sections = [
        ("A", "A records"),
        ("AAAA", "AAAA records"),
        ("MX", "MX records"),
        ("NS", "NS records"),
        ("CNAME", "CNAME records"),
        ("Certificates", "Certificates"),
        ("Subdomains", "Certificate subdomains"),
        ("Web / HTTP", "Web / HTTP"),
        ("TLS", "TLS"),
    ]
    lines: list[str] = []
    for label, title in sections:
        group = [finding for finding in findings if _domain_record_label(finding) == label]
        if not group:
            continue
        lines.append(f"### {title}")
        for finding in sorted(group, key=lambda item: (item.source, item.value)):
            lines.append(f"- {_short_value(finding.value, limit=160)}")
        lines.append("")
    return lines or ["- None recorded"]


def _render_txt_sections(findings) -> list[str]:
    sections = [
        ("SPF", "SPF"),
        ("DMARC", "DMARC"),
        ("DKIM", "DKIM"),
        ("TXT", "Other TXT"),
    ]
    lines: list[str] = []
    for label, title in sections:
        group = [finding for finding in findings if _domain_record_label(finding) == label]
        if not group:
            continue
        lines.append(f"### {title}")
        for finding in sorted(group, key=lambda item: (item.source, item.value)):
            prefix = "Heuristic provider hint: " if finding.finding_type == "provider_hint" else ""
            lines.append(f"- {prefix}{_short_value(finding.value, limit=180)}")
        lines.append("")
    return lines or ["- None recorded"]


def _render_source_warnings(snapshot: CaseSnapshot) -> list[str]:
    warnings = []
    for investigation in snapshot.source_investigations:
        for error in investigation.errors:
            warnings.append(f"- {error.source}: {error.error}")
    return warnings or ["- None"]


def _render_evidence_artifacts(snapshot: CaseSnapshot) -> list[str]:
    lines = [
        f"- File hashes: {len(snapshot.file_hashes)}",
        f"- Metadata records: {len(snapshot.metadata)}",
        f"- Snapshots: {len(snapshot.snapshots)}",
        f"- Evidence records: {len(snapshot.evidence)}",
    ]
    if snapshot.snapshots:
        lines.append("- Snapshot artifacts:")
        for record in snapshot.snapshots:
            lines.append(f"  - {record.url} (evidence `{_short_id(record.evidence_id)}`)")
    return lines


def _key_priority(finding_type: str) -> int:
    return {
        "registration_record": 0,
        "dns_record": 1,
        "mail_security": 2,
        "web_endpoint": 3,
        "http_redirect": 4,
        "tls_certificate": 5,
        "certificate_record": 6,
        "discovered_domain": 7,
        "provider_hint": 8,
        "discovered_profile": 9,
        "discovered_url": 10,
    }.get(finding_type, 99)


def _confidence_rank(confidence: str) -> int:
    return {"high": 3, "medium": 2, "low": 1}.get(confidence, 0)


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
    if finding.finding_type == "discovered_domain" and finding.source != "email_passive":
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
