"""SQLite-backed case storage."""

from __future__ import annotations

import sqlite3
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator

from .errors import CaseExistsError, CaseNotFoundError
from .models import (
    CaseRecord,
    CaseSnapshot,
    ConnectedEntityRecord,
    EntityRecord,
    FileHashRecord,
    GraphSummaryRecord,
    MetadataRecord,
    NoteRecord,
    RelationshipRecord,
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
}
ALLOWED_CONFIDENCES = {"low", "medium", "high"}


def utc_now_iso() -> str:
    """Return a compact UTC timestamp suitable for SQLite text storage."""

    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


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

        return CaseSnapshot(
            case=CaseRecord(name=case_row["name"], created_at=case_row["created_at"]),
            targets=targets,
            file_hashes=file_hashes,
            metadata=metadata,
            username_scans=username_scans,
            notes=notes,
            entities=entities,
            relationships=relationships,
            graph_summary=graph_summary,
            timeline=timeline,
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
            """
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

    def _entity_record(self, entity_type: str, value: str, note: str) -> EntityRecord:
        return EntityRecord(
            entity_id=str(uuid.uuid4()),
            entity_type=entity_type,
            value=value,
            note=note,
            created_at=utc_now_iso(),
        )

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


def _variant_confidence(variant: UsernameVariant) -> str:
    if variant.confidence is None:
        raise ValueError("Original username variant cannot be related to itself.")
    return variant.confidence
