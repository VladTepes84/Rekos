"""SQLite-backed case storage."""

from __future__ import annotations

import sqlite3
import uuid
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterator, Optional
from urllib.parse import urlparse

from .errors import CaseExistsError, CaseNotFoundError
from .hashfile import sha256_file
from .adapters.base import AdapterResult
from .models import (
    AdapterResultRecord,
    CaseRecord,
    CaseSnapshot,
    ConnectedEntityRecord,
    EntityRecord,
    EvidenceRecord,
    FindingRecord,
    FileHashRecord,
    GraphSummaryRecord,
    InvestigationProfileRecord,
    InvestigationSummaryRecord,
    MetadataRecord,
    NoteRecord,
    RelationshipRecord,
    SearchResultRecord,
    SnapshotRecord,
    SourceInvestigationErrorRecord,
    SourceInvestigationRecord,
    SourceRunRecord,
    TargetRecord,
    TimelineEventRecord,
    UsernameScanRecord,
)
from .paths import case_path, database_path, validate_case_name
from .usernames import UsernameVariant, username_variants


ALLOWED_TARGET_TYPES = {"username"}
ALLOWED_ENTITY_TYPES = {"username", "email", "domain", "url", "ip", "phone", "file", "note"}
ALLOWED_RELATIONSHIP_TYPES = {
    "related_to",
    "possible_match",
    "same_target",
    "referenced_by",
    "extracted_from",
    "discovered_from",
}
ALLOWED_CONFIDENCES = {"low", "medium", "high"}
SEARCH_TYPES = {"entity", "finding", "evidence", "timeline", "note", "relationship"}
TARGET_LIKE_ENTITY_TYPES = {"username", "email", "domain", "url", "ip", "phone"}
TRUSTED_FINDING_SOURCES = {
    "rdap_domain",
    "crtsh_domain",
    "wayback_url",
    "http_snapshot",
    "metadata",
    "snapshot_url",
}
ALLOWED_FINDING_TYPES = {
    "discovered_profile",
    "discovered_domain",
    "discovered_url",
    "metadata_record",
    "archive_record",
    "registration_record",
    "certificate_record",
}


@dataclass(frozen=True)
class _FindingInput:
    finding_type: str
    value: str
    source: str
    confidence: str
    raw_reference: str


@dataclass(frozen=True)
class _ScoreContext:
    targets: set[str]
    usernames: set[str]
    source_runs: dict[str, int]
    source_errors: dict[str, int]
    value_sources: dict[str, set[str]]
    evidence_values: set[str]
    relationship_counts: dict[str, int]


def utc_now_iso() -> str:
    """Return a compact UTC timestamp suitable for SQLite text storage."""

    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def quality_label(score: int) -> str:
    if score >= 75:
        return "high"
    if score >= 45:
        return "medium"
    return "low"


class CaseStore:
    """Persistence boundary for REKOS case state."""

    def __init__(self, cases_root: Path | None = None) -> None:
        self.cases_root = cases_root

    def create_case(self, name: str) -> Path:
        cleaned_name = validate_case_name(name)
        folder = case_path(cleaned_name, self.cases_root)
        if folder.exists():
            raise CaseExistsError(f"Case already exists: {cleaned_name}")

        folder.mkdir(parents=True)
        db_path = database_path(cleaned_name, self.cases_root)
        with self._connect(db_path) as connection:
            self._create_schema(connection)
            connection.execute(
                "INSERT INTO cases (name, created_at) VALUES (?, ?)",
                (cleaned_name, utc_now_iso()),
            )
        return folder

    def add_target(self, case: str, target_type: str, value: str) -> TargetRecord:
        cleaned_type = target_type.strip().lower()
        cleaned_value = value.strip()
        if cleaned_type not in ALLOWED_TARGET_TYPES:
            allowed = ", ".join(sorted(ALLOWED_TARGET_TYPES))
            raise ValueError(f"Unsupported target type '{target_type}'. Allowed: {allowed}.")
        if not cleaned_value:
            raise ValueError("Target value cannot be empty.")

        added_at = utc_now_iso()
        with self.connection_for_case(case) as connection:
            connection.execute(
                "INSERT INTO targets (target_type, value, added_at) VALUES (?, ?, ?)",
                (cleaned_type, cleaned_value, added_at),
            )
        return TargetRecord(target_type=cleaned_type, value=cleaned_value, added_at=added_at)

    def add_file_hash(self, case: str, file_path: Path, sha256: str, size_bytes: int) -> FileHashRecord:
        added_at = utc_now_iso()
        resolved_path = str(file_path)
        with self.connection_for_case(case) as connection:
            connection.execute(
                """
                INSERT INTO file_hashes (path, sha256, size_bytes, added_at)
                VALUES (?, ?, ?, ?)
                """,
                (resolved_path, sha256, size_bytes, added_at),
            )
        return FileHashRecord(
            path=resolved_path,
            sha256=sha256,
            size_bytes=size_bytes,
            added_at=added_at,
        )

    def add_metadata_result(
        self,
        case: str,
        file_path: Path,
        tools: list[str],
        raw_output: str,
        export_path: Path,
    ) -> MetadataRecord:
        added_at = utc_now_iso()
        record = MetadataRecord(
            path=str(file_path),
            tools=", ".join(tools),
            raw_output=raw_output,
            export_path=str(export_path),
            added_at=added_at,
        )
        with self.connection_for_case(case) as connection:
            connection.execute(
                """
                INSERT INTO metadata_findings (path, tools, raw_output, export_path, added_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (record.path, record.tools, record.raw_output, record.export_path, record.added_at),
            )
            self._insert_findings(
                connection,
                [
                    _FindingInput(
                        finding_type="metadata_record",
                        value=record.path,
                        source="metadata",
                        confidence="high",
                        raw_reference=record.export_path,
                    )
                ],
            )
        return record

    def add_username_scan(
        self,
        case: str,
        username: str,
        raw_output: str,
        export_path: Path,
    ) -> UsernameScanRecord:
        added_at = utc_now_iso()
        record = UsernameScanRecord(
            username=username,
            raw_output=raw_output,
            export_path=str(export_path),
            added_at=added_at,
        )
        with self.connection_for_case(case) as connection:
            connection.execute(
                """
                INSERT INTO username_scans (username, raw_output, export_path, added_at)
                VALUES (?, ?, ?, ?)
                """,
                (record.username, record.raw_output, record.export_path, record.added_at),
            )
        return record

    def add_note(self, case: str, text: str) -> NoteRecord:
        cleaned_text = text.strip()
        if not cleaned_text:
            raise ValueError("Note text cannot be empty.")

        added_at = utc_now_iso()
        with self.connection_for_case(case) as connection:
            connection.execute(
                "INSERT INTO notes (text, added_at) VALUES (?, ?)",
                (cleaned_text, added_at),
            )
        return NoteRecord(text=cleaned_text, added_at=added_at)

    def add_entity(
        self,
        case: str,
        entity_type: str,
        value: str,
        note: str = "",
    ) -> EntityRecord:
        cleaned_type = entity_type.strip().lower()
        cleaned_value = value.strip()
        cleaned_note = note.strip()
        if cleaned_type not in ALLOWED_ENTITY_TYPES:
            allowed = ", ".join(sorted(ALLOWED_ENTITY_TYPES))
            raise ValueError(f"Unsupported entity type '{entity_type}'. Allowed: {allowed}.")
        if not cleaned_value:
            raise ValueError("Entity value cannot be empty.")

        record = EntityRecord(
            entity_id=str(uuid.uuid4()),
            entity_type=cleaned_type,
            value=cleaned_value,
            note=cleaned_note,
            created_at=utc_now_iso(),
        )
        with self.connection_for_case(case) as connection:
            connection.execute(
                """
                INSERT INTO entities (entity_id, entity_type, value, note, created_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    record.entity_id,
                    record.entity_type,
                    record.value,
                    record.note,
                    record.created_at,
                ),
            )
            self._insert_timeline_event(
                connection,
                "entity.created",
                f"Created {record.entity_type} entity {record.value}",
            )
        return record

    def ensure_entity(
        self,
        case: str,
        entity_type: str,
        value: str,
        note: str = "",
    ) -> EntityRecord:
        cleaned_type = entity_type.strip().lower()
        cleaned_value = value.strip()
        cleaned_note = note.strip()
        if cleaned_type not in ALLOWED_ENTITY_TYPES:
            allowed = ", ".join(sorted(ALLOWED_ENTITY_TYPES))
            raise ValueError(f"Unsupported entity type '{entity_type}'. Allowed: {allowed}.")
        if not cleaned_value:
            raise ValueError("Entity value cannot be empty.")

        with self.connection_for_case(case) as connection:
            row = connection.execute(
                """
                SELECT entity_id, entity_type, value, note, created_at
                FROM entities
                WHERE entity_type = ? AND value = ?
                ORDER BY id
                LIMIT 1
                """,
                (cleaned_type, cleaned_value),
            ).fetchone()
            if row is not None:
                return EntityRecord(
                    entity_id=row["entity_id"],
                    entity_type=row["entity_type"],
                    value=row["value"],
                    note=row["note"],
                    created_at=row["created_at"],
                )

            record = self._entity_record(cleaned_type, cleaned_value, cleaned_note)
            self._insert_entity(connection, record)
            self._insert_timeline_event(
                connection,
                "entity.created",
                f"Created {record.entity_type} entity {record.value}",
            )
            return record

    def relate_entities(
        self,
        case: str,
        source_entity_id: str,
        target_entity_id: str,
        relationship_type: str,
        confidence: str,
        note: str = "",
    ) -> RelationshipRecord:
        cleaned_relationship = relationship_type.strip().lower()
        cleaned_confidence = confidence.strip().lower()
        cleaned_note = note.strip()
        if cleaned_relationship not in ALLOWED_RELATIONSHIP_TYPES:
            allowed = ", ".join(sorted(ALLOWED_RELATIONSHIP_TYPES))
            raise ValueError(f"Unsupported relationship type '{relationship_type}'. Allowed: {allowed}.")
        if cleaned_confidence not in ALLOWED_CONFIDENCES:
            allowed = ", ".join(sorted(ALLOWED_CONFIDENCES))
            raise ValueError(f"Unsupported confidence '{confidence}'. Allowed: {allowed}.")
        if source_entity_id == target_entity_id:
            raise ValueError("Relationship endpoints must be different entities.")

        record = RelationshipRecord(
            relationship_id=str(uuid.uuid4()),
            source_entity_id=source_entity_id,
            target_entity_id=target_entity_id,
            relationship_type=cleaned_relationship,
            confidence=cleaned_confidence,
            note=cleaned_note,
            created_at=utc_now_iso(),
        )
        with self.connection_for_case(case) as connection:
            self._require_entity(connection, source_entity_id)
            self._require_entity(connection, target_entity_id)
            connection.execute(
                """
                INSERT INTO relationships (
                    relationship_id,
                    source_entity_id,
                    target_entity_id,
                    relationship_type,
                    confidence,
                    note,
                    created_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    record.relationship_id,
                    record.source_entity_id,
                    record.target_entity_id,
                    record.relationship_type,
                    record.confidence,
                    record.note,
                    record.created_at,
                ),
            )
            self._insert_timeline_event(
                connection,
                "relationship.created",
                f"Created {record.relationship_type} relationship",
            )
        return record

    def list_entities(self, case: str) -> list[EntityRecord]:
        with self.connection_for_case(case) as connection:
            return self._load_entities(connection)

    def graph_summary(self, case: str) -> GraphSummaryRecord:
        with self.connection_for_case(case) as connection:
            return self._graph_summary(connection)

    def add_timeline_event(self, case: str, event_type: str, summary: str) -> None:
        with self.connection_for_case(case) as connection:
            self._insert_timeline_event(connection, event_type, summary)

    def add_username_target(self, case: str, username: str) -> tuple[EntityRecord, list[EntityRecord]]:
        variants = username_variants(username)
        original_variant = variants[0]
        original_record = self._entity_record("username", original_variant.value, "original username target")
        variant_records = [
            self._entity_record("username", variant.value, "username variant")
            for variant in variants[1:]
        ]

        with self.connection_for_case(case) as connection:
            self._insert_entity(connection, original_record)
            self._insert_timeline_event(
                connection,
                "entity.created",
                f"Created username entity {original_record.value}",
            )
            for variant, record in zip(variants[1:], variant_records):
                self._insert_entity(connection, record)
                self._insert_timeline_event(
                    connection,
                    "entity.created",
                    f"Created username variant entity {record.value}",
                )
                self._insert_relationship(
                    connection,
                    source_entity_id=original_record.entity_id,
                    target_entity_id=record.entity_id,
                    relationship_type="possible_match",
                    confidence=_variant_confidence(variant),
                    note="username variant correlation",
                )
        return original_record, variant_records

    def add_username_investigation(
        self,
        case: str,
        username: str,
        variants: list[UsernameVariant],
        profiles: list[dict[str, str]],
    ) -> InvestigationSummaryRecord:
        if not variants:
            raise ValueError("Investigation requires at least one username variant.")

        created_at = utc_now_iso()
        original_record = self._entity_record("username", variants[0].value, "investigation username")
        variant_records = [
            self._entity_record("username", variant.value, "investigation username variant")
            for variant in variants[1:]
        ]
        profile_records = [
            InvestigationProfileRecord(
                source_username=profile["source_username"],
                profile_url=profile["profile_url"],
                confidence=profile["confidence"],
                export_path=profile["export_path"],
                created_at=created_at,
            )
            for profile in profiles
        ]

        with self.connection_for_case(case) as connection:
            self._insert_entity(connection, original_record)
            self._insert_timeline_event(
                connection,
                "entity.created",
                f"Created investigation username entity {original_record.value}",
            )
            username_entities = {original_record.value: original_record}
            for variant, record in zip(variants[1:], variant_records):
                self._insert_entity(connection, record)
                username_entities[record.value] = record
                self._insert_timeline_event(
                    connection,
                    "entity.created",
                    f"Created investigation username variant entity {record.value}",
                )
                self._insert_relationship(
                    connection,
                    source_entity_id=original_record.entity_id,
                    target_entity_id=record.entity_id,
                    relationship_type="possible_match",
                    confidence=_variant_confidence(variant),
                    note="username variant correlation",
                )

            connection.execute(
                """
                INSERT INTO investigations (username, variant_count, profile_count, created_at)
                VALUES (?, ?, ?, ?)
                """,
                (username, len(variants), len(profile_records), created_at),
            )
            investigation_id = connection.execute("SELECT last_insert_rowid()").fetchone()[0]

            for profile in profile_records:
                profile_entity = self._entity_record(
                    "url",
                    profile.profile_url,
                    f"profile discovered from {profile.source_username}",
                )
                self._insert_entity(connection, profile_entity)
                self._insert_timeline_event(
                    connection,
                    "entity.created",
                    f"Created profile URL entity {profile.profile_url}",
                )
                source_entity = username_entities[profile.source_username]
                self._insert_relationship(
                    connection,
                    source_entity_id=source_entity.entity_id,
                    target_entity_id=profile_entity.entity_id,
                    relationship_type="discovered_from",
                    confidence=profile.confidence,
                    note="profile URL discovered by username investigation",
                )
                self._insert_relationship(
                    connection,
                    source_entity_id=original_record.entity_id,
                    target_entity_id=profile_entity.entity_id,
                    relationship_type="same_target",
                    confidence=profile.confidence,
                    note="profile URL correlated to investigated username",
                )
                connection.execute(
                    """
                    INSERT INTO investigation_profiles (
                        investigation_id,
                        source_username,
                        profile_url,
                        confidence,
                        export_path,
                        created_at
                    )
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        investigation_id,
                        profile.source_username,
                        profile.profile_url,
                        profile.confidence,
                        profile.export_path,
                        profile.created_at,
                    ),
                )

            self._insert_timeline_event(
                connection,
                "investigation.completed",
                f"Completed username investigation for {username}",
            )

        return InvestigationSummaryRecord(
            username=username,
            variant_count=len(variants),
            profile_count=len(profile_records),
            created_at=created_at,
            profiles=profile_records,
        )

    def investigations(self, case: str) -> list[InvestigationSummaryRecord]:
        with self.connection_for_case(case) as connection:
            return self._load_investigations(connection)

    def add_source_investigation(
        self,
        case: str,
        target_type: str,
        target: str,
        source_count: int,
        result_count: int,
        skipped_count: int,
        failed_count: int,
        errors: list[tuple[str, str]],
    ) -> SourceInvestigationRecord:
        cleaned_type = target_type.strip().lower()
        cleaned_target = target.strip()
        if cleaned_type not in {"domain", "url"}:
            raise ValueError("Source investigation target type must be domain or url.")
        if not cleaned_target:
            raise ValueError("Source investigation target cannot be empty.")

        created_at = utc_now_iso()
        error_records = [
            SourceInvestigationErrorRecord(source=source, error=error)
            for source, error in errors
        ]
        with self.connection_for_case(case) as connection:
            connection.execute(
                """
                INSERT INTO source_investigations (
                    target_type,
                    target,
                    source_count,
                    result_count,
                    skipped_count,
                    failed_count,
                    created_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    cleaned_type,
                    cleaned_target,
                    source_count,
                    result_count,
                    skipped_count,
                    failed_count,
                    created_at,
                ),
            )
            investigation_id = connection.execute("SELECT last_insert_rowid()").fetchone()[0]
            connection.executemany(
                """
                INSERT INTO source_investigation_errors (
                    investigation_id,
                    source,
                    error
                )
                VALUES (?, ?, ?)
                """,
                [
                    (investigation_id, error.source, error.error)
                    for error in error_records
                ],
            )
            self._insert_timeline_event(
                connection,
                "investigation.completed",
                f"Completed {cleaned_type} investigation for {cleaned_target}",
            )

        return SourceInvestigationRecord(
            target_type=cleaned_type,
            target=cleaned_target,
            source_count=source_count,
            result_count=result_count,
            skipped_count=skipped_count,
            failed_count=failed_count,
            created_at=created_at,
            errors=error_records,
        )

    def source_investigations(self, case: str) -> list[SourceInvestigationRecord]:
        with self.connection_for_case(case) as connection:
            return self._load_source_investigations(connection)

    def add_adapter_results(self, case: str, results: list[AdapterResult]) -> list[AdapterResultRecord]:
        created_at = utc_now_iso()
        records = [
            AdapterResultRecord(
                source=result.source,
                target=result.target,
                url=result.url,
                platform=result.platform,
                confidence=result.confidence,
                raw_reference=result.raw_reference,
                created_at=created_at,
            )
            for result in results
        ]
        if not records:
            return []
        with self.connection_for_case(case) as connection:
            connection.executemany(
                """
                INSERT INTO adapter_results (
                    source,
                    target,
                    url,
                    platform,
                    confidence,
                    raw_reference,
                    created_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                [
                    (
                        record.source,
                        record.target,
                        record.url,
                        record.platform,
                        record.confidence,
                        record.raw_reference,
                        record.created_at,
                    )
                    for record in records
                ],
            )
            self._insert_findings(
                connection,
                _findings_from_adapter_results(results),
            )
        return records

    def findings(self, case: str) -> list[FindingRecord]:
        with self.connection_for_case(case) as connection:
            return self._load_findings(connection)

    def score_findings(self, case: str) -> list[FindingRecord]:
        with self.connection_for_case(case) as connection:
            findings = self._load_findings(connection)
            context = _score_context(connection)
            updates: list[tuple[int, str, str]] = []
            for finding in findings:
                score, reason = _score_finding(finding, context)
                updates.append((score, reason, finding.finding_id))
            connection.executemany(
                """
                UPDATE normalized_findings
                SET quality_score = ?, quality_reason = ?
                WHERE finding_id = ?
                """,
                updates,
            )
            self._insert_timeline_event(
                connection,
                "findings.scored",
                f"Scored {len(updates)} normalized findings for correlation quality",
            )
            return self._load_findings(connection)

    def search(
        self,
        case: str,
        query: str,
        result_type: str | None = None,
        source: str | None = None,
        confidence: str | None = None,
    ) -> list[SearchResultRecord]:
        cleaned_query = query.strip().lower()
        if not cleaned_query:
            raise ValueError("Search query cannot be empty.")
        cleaned_type = result_type.strip().lower() if result_type else None
        if cleaned_type and cleaned_type not in SEARCH_TYPES:
            allowed = ", ".join(sorted(SEARCH_TYPES))
            raise ValueError(f"Unsupported search type '{result_type}'. Allowed: {allowed}.")
        cleaned_source = source.strip().lower() if source else None
        cleaned_confidence = confidence.strip().lower() if confidence else None
        if cleaned_confidence and cleaned_confidence not in ALLOWED_CONFIDENCES:
            allowed = ", ".join(sorted(ALLOWED_CONFIDENCES))
            raise ValueError(f"Unsupported confidence '{confidence}'. Allowed: {allowed}.")

        with self.connection_for_case(case) as connection:
            results: list[SearchResultRecord] = []
            if cleaned_type in {None, "entity"}:
                results.extend(_search_entities(connection, cleaned_query))
            if cleaned_type in {None, "relationship"}:
                results.extend(_search_relationships(connection, cleaned_query))
            if cleaned_type in {None, "finding"}:
                results.extend(_search_findings(connection, cleaned_query))
            if cleaned_type in {None, "evidence"}:
                results.extend(_search_evidence(connection, cleaned_query))
            if cleaned_type in {None, "timeline"}:
                results.extend(_search_timeline(connection, cleaned_query))
            if cleaned_type in {None, "note"}:
                results.extend(_search_notes(connection, cleaned_query))

        return [
            result
            for result in results
            if _record_matches_filters(result, cleaned_source, cleaned_confidence)
        ]

    def target_like_entities(self, case: str) -> list[EntityRecord]:
        with self.connection_for_case(case) as connection:
            return [
                EntityRecord(
                    entity_id=row["entity_id"],
                    entity_type=row["entity_type"],
                    value=row["value"],
                    note=row["note"],
                    created_at=row["created_at"],
                )
                for row in connection.execute(
                    """
                    SELECT entity_id, entity_type, value, note, created_at
                    FROM entities
                    WHERE entity_type IN (?, ?, ?, ?, ?, ?)
                    ORDER BY entity_type, value
                    """,
                    tuple(sorted(TARGET_LIKE_ENTITY_TYPES)),
                ).fetchall()
            ]

    def source_runs(self, case: str) -> list[SourceRunRecord]:
        with self.connection_for_case(case) as connection:
            finding_counts = {
                row["source"]: row["count"]
                for row in connection.execute(
                    """
                    SELECT source, COUNT(*) AS count
                    FROM normalized_findings
                    GROUP BY source
                    """
                ).fetchall()
            }
            runs = [
                SourceRunRecord(
                    source=row["source"],
                    target=row["target"],
                    status="ok",
                    findings_count=finding_counts.get(row["source"], 0),
                    error="",
                    created_at=row["created_at"],
                )
                for row in connection.execute(
                    """
                    SELECT source, target, created_at, COUNT(*) AS result_count
                    FROM adapter_results
                    GROUP BY source, target, created_at
                    ORDER BY created_at, source, target
                    """
                ).fetchall()
            ]
            error_runs = [
                SourceRunRecord(
                    source=row["source"],
                    target=row["target"],
                    status="skipped"
                    if row["error"].startswith("Missing dependencies:")
                    else "failed",
                    findings_count=finding_counts.get(row["source"], 0),
                    error=row["error"],
                    created_at=row["created_at"],
                )
                for row in connection.execute(
                    """
                    SELECT e.source, e.error, i.target, i.created_at
                    FROM source_investigation_errors e
                    JOIN source_investigations i
                        ON i.id = e.investigation_id
                    ORDER BY i.created_at, e.source
                    """
                ).fetchall()
            ]
        return [*runs, *error_runs]

    def recent_snapshot(
        self,
        case: str,
        url: str,
        interval_seconds: int,
    ) -> Optional[SnapshotRecord]:
        cutoff = datetime.now(timezone.utc) - timedelta(seconds=interval_seconds)
        with self.connection_for_case(case) as connection:
            row = connection.execute(
                """
                SELECT url, captured_at, status_code, headers_path, body_path,
                       screenshot_path, evidence_id
                FROM snapshots
                WHERE url = ?
                ORDER BY id DESC
                LIMIT 1
                """,
                (url,),
            ).fetchone()
        if row is None:
            return None
        captured_at = datetime.fromisoformat(row["captured_at"])
        if captured_at < cutoff:
            return None
        return SnapshotRecord(
            url=row["url"],
            captured_at=row["captured_at"],
            status_code=row["status_code"],
            headers_path=row["headers_path"],
            body_path=row["body_path"],
            screenshot_path=row["screenshot_path"],
            evidence_id=row["evidence_id"],
        )

    def add_url_snapshot(
        self,
        case: str,
        url: str,
        status_code: Optional[int],
        headers_path: Path,
        body_path: Path,
        screenshot_path: Optional[Path],
    ) -> SnapshotRecord:
        captured_at = utc_now_iso()
        evidence_id = str(uuid.uuid4())
        digest, _size_bytes = sha256_file(body_path)
        record = SnapshotRecord(
            url=url,
            captured_at=captured_at,
            status_code=status_code,
            headers_path=str(headers_path),
            body_path=str(body_path),
            screenshot_path=str(screenshot_path or ""),
            evidence_id=evidence_id,
        )
        with self.connection_for_case(case) as connection:
            self._ensure_url_entity(connection, url)
            connection.execute(
                """
                INSERT INTO evidence (evidence_id, type, path, sha256, created_at, source_url, note)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    evidence_id,
                    "url_snapshot",
                    str(body_path),
                    digest,
                    captured_at,
                    url,
                    "Public URL snapshot body artifact",
                ),
            )
            connection.execute(
                """
                INSERT INTO snapshots (
                    url,
                    captured_at,
                    status_code,
                    headers_path,
                    body_path,
                    screenshot_path,
                    evidence_id
                )
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    record.url,
                    record.captured_at,
                    record.status_code,
                    record.headers_path,
                    record.body_path,
                    record.screenshot_path,
                    record.evidence_id,
                ),
            )
            self._insert_timeline_event(
                connection,
                "snapshot.created",
                f"Captured public URL snapshot {url}",
            )
            self._insert_findings(
                connection,
                [
                    _FindingInput(
                        finding_type="metadata_record",
                        value=url,
                        source="snapshot_url",
                        confidence="high",
                        raw_reference=str(body_path),
                    )
                ],
            )
        return record

    def snapshot(self, case: str) -> CaseSnapshot:
        with self.connection_for_case(case) as connection:
            case_row = connection.execute(
                "SELECT name, created_at FROM cases LIMIT 1"
            ).fetchone()
            if case_row is None:
                raise CaseNotFoundError(f"Case metadata is missing: {case}")

            targets = [
                TargetRecord(
                    target_type=row["target_type"],
                    value=row["value"],
                    added_at=row["added_at"],
                )
                for row in connection.execute(
                    "SELECT target_type, value, added_at FROM targets ORDER BY id"
                ).fetchall()
            ]
            file_hashes = [
                FileHashRecord(
                    path=row["path"],
                    sha256=row["sha256"],
                    size_bytes=row["size_bytes"],
                    added_at=row["added_at"],
                )
                for row in connection.execute(
                    "SELECT path, sha256, size_bytes, added_at FROM file_hashes ORDER BY id"
                ).fetchall()
            ]
            evidence = [
                EvidenceRecord(
                    evidence_id=row["evidence_id"],
                    evidence_type=row["type"],
                    path=row["path"],
                    sha256=row["sha256"],
                    created_at=row["created_at"],
                    source_url=row["source_url"],
                    note=row["note"],
                )
                for row in connection.execute(
                    """
                    SELECT evidence_id, type, path, sha256, created_at, source_url, note
                    FROM evidence
                    ORDER BY id
                    """
                ).fetchall()
            ]
            metadata = [
                MetadataRecord(
                    path=row["path"],
                    tools=row["tools"],
                    raw_output=row["raw_output"],
                    export_path=row["export_path"],
                    added_at=row["added_at"],
                )
                for row in connection.execute(
                    """
                    SELECT path, tools, raw_output, export_path, added_at
                    FROM metadata_findings
                    ORDER BY id
                    """
                ).fetchall()
            ]
            username_scans = [
                UsernameScanRecord(
                    username=row["username"],
                    raw_output=row["raw_output"],
                    export_path=row["export_path"],
                    added_at=row["added_at"],
                )
                for row in connection.execute(
                    """
                    SELECT username, raw_output, export_path, added_at
                    FROM username_scans
                    ORDER BY id
                    """
                ).fetchall()
            ]
            notes = [
                NoteRecord(text=row["text"], added_at=row["added_at"])
                for row in connection.execute(
                    "SELECT text, added_at FROM notes ORDER BY id"
                ).fetchall()
            ]
            entities = self._load_entities(connection)
            relationships = [
                RelationshipRecord(
                    relationship_id=row["relationship_id"],
                    source_entity_id=row["source_entity_id"],
                    target_entity_id=row["target_entity_id"],
                    relationship_type=row["relationship_type"],
                    confidence=row["confidence"],
                    note=row["note"],
                    created_at=row["created_at"],
                )
                for row in connection.execute(
                    """
                    SELECT relationship_id, source_entity_id, target_entity_id,
                           relationship_type, confidence, note, created_at
                    FROM relationships
                    ORDER BY id
                    """
                ).fetchall()
            ]
            timeline = [
                TimelineEventRecord(
                    event_type=row["event_type"],
                    summary=row["summary"],
                    created_at=row["created_at"],
                )
                for row in connection.execute(
                    "SELECT event_type, summary, created_at FROM timeline_events ORDER BY id"
                ).fetchall()
            ]
            graph_summary = self._graph_summary(connection)
            investigations = self._load_investigations(connection)
            source_investigations = self._load_source_investigations(connection)
            adapter_results = [
                AdapterResultRecord(
                    source=row["source"],
                    target=row["target"],
                    url=row["url"],
                    platform=row["platform"],
                    confidence=row["confidence"],
                    raw_reference=row["raw_reference"],
                    created_at=row["created_at"],
                )
                for row in connection.execute(
                    """
                    SELECT source, target, url, platform, confidence, raw_reference, created_at
                    FROM adapter_results
                    ORDER BY id
                    """
                ).fetchall()
            ]
            findings = self._load_findings(connection)
            snapshots = [
                SnapshotRecord(
                    url=row["url"],
                    captured_at=row["captured_at"],
                    status_code=row["status_code"],
                    headers_path=row["headers_path"],
                    body_path=row["body_path"],
                    screenshot_path=row["screenshot_path"],
                    evidence_id=row["evidence_id"],
                )
                for row in connection.execute(
                    """
                    SELECT url, captured_at, status_code, headers_path, body_path,
                           screenshot_path, evidence_id
                    FROM snapshots
                    ORDER BY id
                    """
                ).fetchall()
            ]

        return CaseSnapshot(
            case=CaseRecord(name=case_row["name"], created_at=case_row["created_at"]),
            targets=targets,
            file_hashes=file_hashes,
            evidence=evidence,
            metadata=metadata,
            username_scans=username_scans,
            notes=notes,
            entities=entities,
            relationships=relationships,
            graph_summary=graph_summary,
            timeline=timeline,
            investigations=investigations,
            source_investigations=source_investigations,
            adapter_results=adapter_results,
            findings=findings,
            snapshots=snapshots,
        )

    def exports_folder(self, case: str) -> Path:
        folder = case_path(case, self.cases_root)
        db_path = database_path(case, self.cases_root)
        if not db_path.exists():
            raise CaseNotFoundError(f"Case not found: {validate_case_name(case)}")
        exports = folder / "exports"
        exports.mkdir(exist_ok=True)
        return exports

    @contextmanager
    def connection_for_case(self, case: str) -> Iterator[sqlite3.Connection]:
        db_path = database_path(case, self.cases_root)
        if not db_path.exists():
            raise CaseNotFoundError(f"Case not found: {validate_case_name(case)}")

        with self._connect(db_path) as connection:
            self._create_schema(connection)
            yield connection

    @contextmanager
    def _connect(self, db_path: Path) -> Iterator[sqlite3.Connection]:
        connection = sqlite3.connect(db_path)
        connection.row_factory = sqlite3.Row
        try:
            connection.execute("PRAGMA foreign_keys = ON")
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def _create_schema(self, connection: sqlite3.Connection) -> None:
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS cases (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                name TEXT NOT NULL UNIQUE,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS targets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target_type TEXT NOT NULL,
                value TEXT NOT NULL,
                added_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS file_hashes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                path TEXT NOT NULL,
                sha256 TEXT NOT NULL,
                size_bytes INTEGER NOT NULL,
                added_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS notes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                text TEXT NOT NULL,
                added_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS evidence (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                evidence_id TEXT NOT NULL UNIQUE,
                type TEXT NOT NULL,
                path TEXT NOT NULL,
                sha256 TEXT NOT NULL,
                created_at TEXT NOT NULL,
                source_url TEXT NOT NULL,
                note TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS metadata_findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                path TEXT NOT NULL,
                tools TEXT NOT NULL,
                raw_output TEXT NOT NULL,
                export_path TEXT NOT NULL,
                added_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS username_scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                raw_output TEXT NOT NULL,
                export_path TEXT NOT NULL,
                added_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS entities (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                entity_id TEXT NOT NULL UNIQUE,
                entity_type TEXT NOT NULL,
                value TEXT NOT NULL,
                note TEXT NOT NULL,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS relationships (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                relationship_id TEXT NOT NULL UNIQUE,
                source_entity_id TEXT NOT NULL,
                target_entity_id TEXT NOT NULL,
                relationship_type TEXT NOT NULL,
                confidence TEXT NOT NULL,
                note TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY (source_entity_id) REFERENCES entities (entity_id),
                FOREIGN KEY (target_entity_id) REFERENCES entities (entity_id)
            );

            CREATE TABLE IF NOT EXISTS timeline_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_type TEXT NOT NULL,
                summary TEXT NOT NULL,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS investigations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                variant_count INTEGER NOT NULL,
                profile_count INTEGER NOT NULL,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS investigation_profiles (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                investigation_id INTEGER NOT NULL,
                source_username TEXT NOT NULL,
                profile_url TEXT NOT NULL,
                confidence TEXT NOT NULL,
                export_path TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY (investigation_id) REFERENCES investigations (id)
            );

            CREATE TABLE IF NOT EXISTS adapter_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                source TEXT NOT NULL,
                target TEXT NOT NULL,
                url TEXT NOT NULL,
                platform TEXT NOT NULL,
                confidence TEXT NOT NULL,
                raw_reference TEXT NOT NULL,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS normalized_findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                finding_id TEXT NOT NULL UNIQUE,
                type TEXT NOT NULL,
                value TEXT NOT NULL,
                source TEXT NOT NULL,
                confidence TEXT NOT NULL,
                quality_score INTEGER NOT NULL DEFAULT 0,
                quality_reason TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL,
                raw_reference TEXT NOT NULL,
                UNIQUE(type, value, source)
            );

            CREATE TABLE IF NOT EXISTS source_investigations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target_type TEXT NOT NULL,
                target TEXT NOT NULL,
                source_count INTEGER NOT NULL,
                result_count INTEGER NOT NULL,
                skipped_count INTEGER NOT NULL,
                failed_count INTEGER NOT NULL,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS source_investigation_errors (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                investigation_id INTEGER NOT NULL,
                source TEXT NOT NULL,
                error TEXT NOT NULL,
                FOREIGN KEY (investigation_id) REFERENCES source_investigations (id)
            );

            CREATE TABLE IF NOT EXISTS snapshots (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT NOT NULL,
                captured_at TEXT NOT NULL,
                status_code INTEGER,
                headers_path TEXT NOT NULL,
                body_path TEXT NOT NULL,
                screenshot_path TEXT NOT NULL,
                evidence_id TEXT NOT NULL,
                FOREIGN KEY (evidence_id) REFERENCES evidence (evidence_id)
            );
            """
        )
        _ensure_column(
            connection,
            "normalized_findings",
            "quality_score",
            "INTEGER NOT NULL DEFAULT 0",
        )
        _ensure_column(
            connection,
            "normalized_findings",
            "quality_reason",
            "TEXT NOT NULL DEFAULT ''",
        )

    def _load_entities(self, connection: sqlite3.Connection) -> list[EntityRecord]:
        return [
            EntityRecord(
                entity_id=row["entity_id"],
                entity_type=row["entity_type"],
                value=row["value"],
                note=row["note"],
                created_at=row["created_at"],
            )
            for row in connection.execute(
                """
                SELECT entity_id, entity_type, value, note, created_at
                FROM entities
                ORDER BY id
                """
            ).fetchall()
        ]

    def _graph_summary(self, connection: sqlite3.Connection) -> GraphSummaryRecord:
        total_entities = connection.execute("SELECT COUNT(*) FROM entities").fetchone()[0]
        total_relationships = connection.execute("SELECT COUNT(*) FROM relationships").fetchone()[0]
        type_counts = {
            row["entity_type"]: row["count"]
            for row in connection.execute(
                """
                SELECT entity_type, COUNT(*) AS count
                FROM entities
                GROUP BY entity_type
                ORDER BY entity_type
                """
            ).fetchall()
        }
        most_connected = [
            ConnectedEntityRecord(
                entity_id=row["entity_id"],
                entity_type=row["entity_type"],
                value=row["value"],
                connection_count=row["connection_count"],
            )
            for row in connection.execute(
                """
                SELECT e.entity_id, e.entity_type, e.value, COUNT(r.relationship_id) AS connection_count
                FROM entities e
                LEFT JOIN relationships r
                    ON r.source_entity_id = e.entity_id
                    OR r.target_entity_id = e.entity_id
                GROUP BY e.entity_id, e.entity_type, e.value
                HAVING connection_count > 0
                ORDER BY connection_count DESC, e.value
                LIMIT 5
                """
            ).fetchall()
        ]
        return GraphSummaryRecord(
            total_entities=total_entities,
            total_relationships=total_relationships,
            entity_type_counts=type_counts,
            most_connected=most_connected,
        )

    def _load_investigations(self, connection: sqlite3.Connection) -> list[InvestigationSummaryRecord]:
        investigations: list[InvestigationSummaryRecord] = []
        for row in connection.execute(
            """
            SELECT id, username, variant_count, profile_count, created_at
            FROM investigations
            ORDER BY id
            """
        ).fetchall():
            profiles = [
                InvestigationProfileRecord(
                    source_username=profile["source_username"],
                    profile_url=profile["profile_url"],
                    confidence=profile["confidence"],
                    export_path=profile["export_path"],
                    created_at=profile["created_at"],
                )
                for profile in connection.execute(
                    """
                    SELECT source_username, profile_url, confidence, export_path, created_at
                    FROM investigation_profiles
                    WHERE investigation_id = ?
                    ORDER BY id
                    """,
                    (row["id"],),
                ).fetchall()
            ]
            investigations.append(
                InvestigationSummaryRecord(
                    username=row["username"],
                    variant_count=row["variant_count"],
                    profile_count=row["profile_count"],
                    created_at=row["created_at"],
                    profiles=profiles,
                )
            )
        return investigations

    def _load_findings(self, connection: sqlite3.Connection) -> list[FindingRecord]:
        return [
            FindingRecord(
                finding_id=row["finding_id"],
                finding_type=row["type"],
                value=row["value"],
                source=row["source"],
                confidence=row["confidence"],
                quality_score=row["quality_score"],
                quality_reason=row["quality_reason"],
                created_at=row["created_at"],
                raw_reference=row["raw_reference"],
            )
            for row in connection.execute(
                """
                SELECT finding_id, type, value, source, confidence,
                       quality_score, quality_reason,
                       created_at, raw_reference
                FROM normalized_findings
                ORDER BY id
                """
            ).fetchall()
        ]

    def _load_source_investigations(
        self,
        connection: sqlite3.Connection,
    ) -> list[SourceInvestigationRecord]:
        investigations: list[SourceInvestigationRecord] = []
        for row in connection.execute(
            """
            SELECT id, target_type, target, source_count, result_count,
                   skipped_count, failed_count, created_at
            FROM source_investigations
            ORDER BY id
            """
        ).fetchall():
            errors = [
                SourceInvestigationErrorRecord(
                    source=error["source"],
                    error=error["error"],
                )
                for error in connection.execute(
                    """
                    SELECT source, error
                    FROM source_investigation_errors
                    WHERE investigation_id = ?
                    ORDER BY id
                    """,
                    (row["id"],),
                ).fetchall()
            ]
            investigations.append(
                SourceInvestigationRecord(
                    target_type=row["target_type"],
                    target=row["target"],
                    source_count=row["source_count"],
                    result_count=row["result_count"],
                    skipped_count=row["skipped_count"],
                    failed_count=row["failed_count"],
                    created_at=row["created_at"],
                    errors=errors,
                )
            )
        return investigations

    def _entity_record(self, entity_type: str, value: str, note: str) -> EntityRecord:
        return EntityRecord(
            entity_id=str(uuid.uuid4()),
            entity_type=entity_type,
            value=value,
            note=note,
            created_at=utc_now_iso(),
        )

    def _ensure_url_entity(self, connection: sqlite3.Connection, url: str) -> EntityRecord:
        row = connection.execute(
            """
            SELECT entity_id, entity_type, value, note, created_at
            FROM entities
            WHERE entity_type = 'url' AND value = ?
            ORDER BY id
            LIMIT 1
            """,
            (url,),
        ).fetchone()
        if row is not None:
            return EntityRecord(
                entity_id=row["entity_id"],
                entity_type=row["entity_type"],
                value=row["value"],
                note=row["note"],
                created_at=row["created_at"],
            )

        record = self._entity_record("url", url, "snapshot URL")
        self._insert_entity(connection, record)
        self._insert_timeline_event(
            connection,
            "entity.created",
            f"Created URL entity {url}",
        )
        return record

    def _insert_entity(
        self,
        connection: sqlite3.Connection,
        record: EntityRecord,
    ) -> None:
        connection.execute(
            """
            INSERT INTO entities (entity_id, entity_type, value, note, created_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                record.entity_id,
                record.entity_type,
                record.value,
                record.note,
                record.created_at,
            ),
        )

    def _insert_relationship(
        self,
        connection: sqlite3.Connection,
        *,
        source_entity_id: str,
        target_entity_id: str,
        relationship_type: str,
        confidence: str,
        note: str,
    ) -> RelationshipRecord:
        record = RelationshipRecord(
            relationship_id=str(uuid.uuid4()),
            source_entity_id=source_entity_id,
            target_entity_id=target_entity_id,
            relationship_type=relationship_type,
            confidence=confidence,
            note=note,
            created_at=utc_now_iso(),
        )
        connection.execute(
            """
            INSERT INTO relationships (
                relationship_id,
                source_entity_id,
                target_entity_id,
                relationship_type,
                confidence,
                note,
                created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                record.relationship_id,
                record.source_entity_id,
                record.target_entity_id,
                record.relationship_type,
                record.confidence,
                record.note,
                record.created_at,
            ),
        )
        self._insert_timeline_event(
            connection,
            "relationship.created",
            f"Created {record.relationship_type} relationship",
        )
        return record

    def _insert_findings(
        self,
        connection: sqlite3.Connection,
        findings: list[_FindingInput],
    ) -> None:
        if not findings:
            return
        created_at = utc_now_iso()
        rows = [
            (
                str(uuid.uuid4()),
                finding.finding_type,
                finding.value,
                finding.source,
                _normalize_confidence(finding.confidence),
                0,
                "",
                created_at,
                finding.raw_reference,
            )
            for finding in _dedupe_finding_inputs(findings)
            if finding.finding_type in ALLOWED_FINDING_TYPES and finding.value
        ]
        if not rows:
            return
        connection.executemany(
            """
            INSERT OR IGNORE INTO normalized_findings (
                finding_id,
                type,
                value,
                source,
                confidence,
                quality_score,
                quality_reason,
                created_at,
                raw_reference
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            rows,
        )

    def _require_entity(self, connection: sqlite3.Connection, entity_id: str) -> None:
        row = connection.execute(
            "SELECT entity_id FROM entities WHERE entity_id = ?",
            (entity_id,),
        ).fetchone()
        if row is None:
            raise ValueError(f"Entity not found: {entity_id}")

    def _insert_timeline_event(
        self,
        connection: sqlite3.Connection,
        event_type: str,
        summary: str,
    ) -> None:
        connection.execute(
            """
            INSERT INTO timeline_events (event_type, summary, created_at)
            VALUES (?, ?, ?)
            """,
            (event_type, summary, utc_now_iso()),
        )


def _search_entities(
    connection: sqlite3.Connection,
    query: str,
) -> list[SearchResultRecord]:
    return [
        SearchResultRecord(
            result_type="entity",
            subtype=row["entity_type"],
            value=row["value"],
            source="",
            confidence="",
            context=row["note"] or row["entity_id"],
            created_at=row["created_at"],
        )
        for row in connection.execute(
            """
            SELECT entity_id, entity_type, value, note, created_at
            FROM entities
            ORDER BY id
            """
        ).fetchall()
        if _contains_query(query, row["entity_id"], row["entity_type"], row["value"], row["note"])
    ]


def _search_relationships(
    connection: sqlite3.Connection,
    query: str,
) -> list[SearchResultRecord]:
    return [
        SearchResultRecord(
            result_type="relationship",
            subtype=row["relationship_type"],
            value=f"{row['source_entity_id']} -> {row['target_entity_id']}",
            source="",
            confidence=row["confidence"],
            context=row["note"] or row["relationship_id"],
            created_at=row["created_at"],
        )
        for row in connection.execute(
            """
            SELECT relationship_id, source_entity_id, target_entity_id,
                   relationship_type, confidence, note, created_at
            FROM relationships
            ORDER BY id
            """
        ).fetchall()
        if _contains_query(
            query,
            row["relationship_id"],
            row["source_entity_id"],
            row["target_entity_id"],
            row["relationship_type"],
            row["confidence"],
            row["note"],
        )
    ]


def _search_findings(
    connection: sqlite3.Connection,
    query: str,
) -> list[SearchResultRecord]:
    return [
        SearchResultRecord(
            result_type="finding",
            subtype=row["type"],
            value=row["value"],
            source=row["source"],
            confidence=row["confidence"],
            context=row["raw_reference"],
            created_at=row["created_at"],
        )
        for row in connection.execute(
            """
            SELECT finding_id, type, value, source, confidence,
                   created_at, raw_reference
            FROM normalized_findings
            ORDER BY id
            """
        ).fetchall()
        if _contains_query(
            query,
            row["finding_id"],
            row["type"],
            row["value"],
            row["source"],
            row["confidence"],
            row["raw_reference"],
        )
    ]


def _search_evidence(
    connection: sqlite3.Connection,
    query: str,
) -> list[SearchResultRecord]:
    return [
        SearchResultRecord(
            result_type="evidence",
            subtype=row["type"],
            value=row["path"],
            source=row["source_url"],
            confidence="",
            context=row["note"] or row["sha256"],
            created_at=row["created_at"],
        )
        for row in connection.execute(
            """
            SELECT evidence_id, type, path, sha256, created_at, source_url, note
            FROM evidence
            ORDER BY id
            """
        ).fetchall()
        if _contains_query(
            query,
            row["evidence_id"],
            row["type"],
            row["path"],
            row["sha256"],
            row["source_url"],
            row["note"],
        )
    ]


def _search_timeline(
    connection: sqlite3.Connection,
    query: str,
) -> list[SearchResultRecord]:
    return [
        SearchResultRecord(
            result_type="timeline",
            subtype=row["event_type"],
            value=row["summary"],
            source="",
            confidence="",
            context=row["event_type"],
            created_at=row["created_at"],
        )
        for row in connection.execute(
            """
            SELECT event_type, summary, created_at
            FROM timeline_events
            ORDER BY id
            """
        ).fetchall()
        if _contains_query(query, row["event_type"], row["summary"])
    ]


def _search_notes(
    connection: sqlite3.Connection,
    query: str,
) -> list[SearchResultRecord]:
    return [
        SearchResultRecord(
            result_type="note",
            subtype="note",
            value=row["text"],
            source="",
            confidence="",
            context=row["text"],
            created_at=row["added_at"],
        )
        for row in connection.execute(
            "SELECT text, added_at FROM notes ORDER BY id"
        ).fetchall()
        if _contains_query(query, row["text"])
    ]


def _contains_query(query: str, *values: object) -> bool:
    return any(query in str(value or "").lower() for value in values)


def _record_matches_filters(
    result: SearchResultRecord,
    source: str | None,
    confidence: str | None,
) -> bool:
    if source and result.source.lower() != source:
        return False
    if confidence and result.confidence.lower() != confidence:
        return False
    return True


def _score_context(connection: sqlite3.Connection) -> _ScoreContext:
    targets = {
        row["value"].strip().lower()
        for row in connection.execute("SELECT value FROM targets").fetchall()
        if row["value"]
    }
    targets.update(
        row["target"].strip().lower()
        for row in connection.execute("SELECT target FROM source_investigations").fetchall()
        if row["target"]
    )
    targets.update(
        row["target"].strip().lower()
        for row in connection.execute("SELECT DISTINCT target FROM adapter_results").fetchall()
        if row["target"]
    )
    targets.update(
        row["username"].strip().lower()
        for row in connection.execute("SELECT username FROM investigations").fetchall()
        if row["username"]
    )

    usernames = {
        row["value"].strip()
        for row in connection.execute(
            "SELECT value FROM entities WHERE entity_type = 'username'"
        ).fetchall()
        if row["value"]
    }
    usernames.update(
        row["username"].strip()
        for row in connection.execute("SELECT username FROM investigations").fetchall()
        if row["username"]
    )
    usernames.update(
        row["value"].strip()
        for row in connection.execute(
            "SELECT value FROM targets WHERE target_type = 'username'"
        ).fetchall()
        if row["value"]
    )

    source_runs = {
        row["source"]: row["count"]
        for row in connection.execute(
            """
            SELECT source, COUNT(*) AS count
            FROM adapter_results
            GROUP BY source
            """
        ).fetchall()
    }
    source_errors = {
        row["source"]: row["count"]
        for row in connection.execute(
            """
            SELECT source, COUNT(*) AS count
            FROM source_investigation_errors
            GROUP BY source
            """
        ).fetchall()
    }
    value_sources: dict[str, set[str]] = {}
    for row in connection.execute(
        "SELECT value, source FROM normalized_findings"
    ).fetchall():
        value_sources.setdefault(row["value"].strip().lower(), set()).add(row["source"])

    evidence_values: set[str] = set()
    for row in connection.execute(
        "SELECT path, source_url FROM evidence"
    ).fetchall():
        if row["path"]:
            evidence_values.add(row["path"].strip().lower())
        if row["source_url"]:
            evidence_values.add(row["source_url"].strip().lower())

    relationship_counts = {
        row["value"].strip().lower(): row["connection_count"]
        for row in connection.execute(
            """
            SELECT e.value, COUNT(r.relationship_id) AS connection_count
            FROM entities e
            JOIN relationships r
                ON r.source_entity_id = e.entity_id
                OR r.target_entity_id = e.entity_id
            GROUP BY e.entity_id, e.value
            """
        ).fetchall()
    }
    return _ScoreContext(
        targets=targets,
        usernames=usernames,
        source_runs=source_runs,
        source_errors=source_errors,
        value_sources=value_sources,
        evidence_values=evidence_values,
        relationship_counts=relationship_counts,
    )


def _score_finding(finding: FindingRecord, context: _ScoreContext) -> tuple[int, str]:
    value_key = finding.value.strip().lower()
    raw_key = finding.raw_reference.strip().lower()
    score = 20
    reasons = ["correlation quality only; does not claim identity ownership"]

    confidence_points = {"high": 20, "medium": 12, "low": 4}.get(finding.confidence, 8)
    score += confidence_points
    reasons.append(f"{finding.confidence} source confidence")

    if value_key in context.targets:
        score += 20
        reasons.append("exact target match")

    normalized_usernames = {_normalize_username(username) for username in context.usernames}
    weak_usernames = {_compact_username(username) for username in context.usernames}
    profile_username = _username_from_profile_url(finding.value)
    if profile_username:
        normalized_profile = _normalize_username(profile_username)
        compact_profile = _compact_username(profile_username)
        if normalized_profile in normalized_usernames:
            score += 15
            reasons.append("normalized username match")
        elif compact_profile in weak_usernames:
            score += 6
            reasons.append("weak username variant match")
    elif finding.confidence == "low":
        score += 3
        reasons.append("weak variant-derived finding")

    if finding.source in TRUSTED_FINDING_SOURCES:
        score += 15
        reasons.append("trusted passive source type")

    duplicate_sources = context.value_sources.get(value_key, set())
    if len(duplicate_sources) > 1:
        score += 15
        reasons.append("duplicate confirmation across sources")

    source_run_count = context.source_runs.get(finding.source, 0)
    source_error_count = context.source_errors.get(finding.source, 0)
    total_source_events = source_run_count + source_error_count
    if total_source_events:
        error_rate = source_error_count / total_source_events
        if error_rate == 0:
            score += 5
            reasons.append("no recorded source errors")
        elif error_rate <= 0.25:
            score += 2
            reasons.append("low source error rate")
        elif error_rate >= 0.5:
            score -= 10
            reasons.append("high source error rate")
        else:
            score -= 4
            reasons.append("moderate source error rate")

    if value_key in context.evidence_values or raw_key in context.evidence_values:
        score += 10
        reasons.append("local evidence artifact present")

    relationship_count = context.relationship_counts.get(value_key, 0)
    if relationship_count:
        score += min(10, relationship_count * 2)
        reasons.append(f"{relationship_count} graph relationship(s)")

    bounded_score = max(0, min(100, score))
    reasons.append(f"{quality_label(bounded_score)} quality label")
    return bounded_score, "; ".join(reasons)


def _normalize_username(username: str) -> str:
    return username.strip().lower().lstrip("@")


def _compact_username(username: str) -> str:
    return "".join(char for char in _normalize_username(username) if char.isalnum())


def _username_from_profile_url(value: str) -> str:
    parsed = urlparse(value)
    if not parsed.scheme or not parsed.netloc:
        return ""
    parts = [part for part in parsed.path.split("/") if part]
    if not parts:
        return ""
    return parts[-1]


def _ensure_column(
    connection: sqlite3.Connection,
    table: str,
    column: str,
    definition: str,
) -> None:
    columns = {
        row["name"]
        for row in connection.execute(f"PRAGMA table_info({table})").fetchall()
    }
    if column not in columns:
        connection.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")


def _variant_confidence(variant: UsernameVariant) -> str:
    if variant.confidence is None:
        raise ValueError("Original username variant cannot be related to itself.")
    return variant.confidence


def _findings_from_adapter_results(results: list[AdapterResult]) -> list[_FindingInput]:
    findings: list[_FindingInput] = []
    for result in results:
        source = result.source
        confidence = _normalize_confidence(result.confidence)
        if source in {"sherlock", "sherlock_username", "maigret"}:
            findings.append(
                _FindingInput(
                    finding_type="discovered_profile",
                    value=result.url,
                    source=source,
                    confidence=confidence,
                    raw_reference=result.raw_reference,
                )
            )
            continue

        if source == "rdap_domain":
            findings.append(
                _FindingInput(
                    finding_type="registration_record",
                    value=result.target,
                    source=source,
                    confidence="high",
                    raw_reference=result.raw_reference,
                )
            )
            if not result.url.startswith("https://rdap.org/domain/"):
                findings.append(
                    _FindingInput(
                        finding_type="discovered_url",
                        value=result.url,
                        source=source,
                        confidence="medium",
                        raw_reference=result.raw_reference,
                    )
                )
            continue

        if source == "crtsh_domain":
            domain_value = result.raw_reference or result.url.removeprefix("https://")
            findings.extend(
                [
                    _FindingInput(
                        finding_type="certificate_record",
                        value=domain_value,
                        source=source,
                        confidence="high",
                        raw_reference=result.raw_reference,
                    ),
                    _FindingInput(
                        finding_type="discovered_domain",
                        value=domain_value,
                        source=source,
                        confidence="medium",
                        raw_reference=result.raw_reference,
                    ),
                ]
            )
            continue

        if source == "wayback_url":
            findings.append(
                _FindingInput(
                    finding_type="archive_record",
                    value=result.url,
                    source=source,
                    confidence=confidence,
                    raw_reference=result.raw_reference,
                )
            )
            continue

        if source == "http_snapshot":
            findings.append(
                _FindingInput(
                    finding_type="metadata_record",
                    value=result.url,
                    source=source,
                    confidence="high",
                    raw_reference=result.raw_reference,
                )
            )
            continue

        findings.append(
            _FindingInput(
                finding_type="discovered_url",
                value=result.url,
                source=source,
                confidence=confidence,
                raw_reference=result.raw_reference,
            )
        )
    return findings


def _normalize_confidence(confidence: str) -> str:
    cleaned = confidence.strip().lower()
    if cleaned in ALLOWED_CONFIDENCES:
        return cleaned
    return "medium"


def _dedupe_finding_inputs(findings: list[_FindingInput]) -> list[_FindingInput]:
    deduped: list[_FindingInput] = []
    seen: set[tuple[str, str, str]] = set()
    for finding in findings:
        key = (finding.finding_type, finding.value, finding.source)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(finding)
    return deduped
