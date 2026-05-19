"""SQLite-backed case storage."""

from __future__ import annotations

import sqlite3
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator, Optional

from .errors import CaseExistsError, CaseNotFoundError
from .hashfile import sha256_file
from .models import (
    CaseRecord,
    CaseSnapshot,
    EvidenceRecord,
    FileHashRecord,
    MetadataRecord,
    NoteRecord,
    TargetRecord,
    TimelineEventRecord,
    ValidationSummaryRecord,
    UsernameScanRecord,
)
from .paths import case_path, database_path, validate_case_name


ALLOWED_TARGET_TYPES = {"username"}


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
            created_at = utc_now_iso()
            connection.execute(
                "INSERT INTO cases (name, uuid, created_at) VALUES (?, ?, ?)",
                (cleaned_name, str(uuid.uuid4()), created_at),
            )
            self._insert_timeline_event(connection, "case.created", f"Created case {cleaned_name}")
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
            self._insert_timeline_event(
                connection,
                "target.added",
                f"Added {cleaned_type} target {cleaned_value}",
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
            self._insert_evidence(
                connection,
                evidence_type="file",
                path=resolved_path,
                sha256=sha256,
                created_at=added_at,
                source_url=None,
                note=f"Hashed file ({size_bytes} bytes)",
            )
            self._insert_timeline_event(connection, "file.hashed", f"Hashed file {file_path.name}")
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
        export_sha256, _size_bytes = sha256_file(export_path)
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
            self._insert_evidence(
                connection,
                evidence_type="metadata_export",
                path=record.export_path,
                sha256=export_sha256,
                created_at=added_at,
                source_url=None,
                note=f"Metadata output for {file_path.name}",
            )
            self._insert_timeline_event(
                connection,
                "metadata.collected",
                f"Collected metadata for {file_path.name}",
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
        export_sha256, _size_bytes = sha256_file(export_path)
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
            self._insert_evidence(
                connection,
                evidence_type="username_scan_export",
                path=record.export_path,
                sha256=export_sha256,
                created_at=added_at,
                source_url=None,
                note=f"Username scan output for {username}",
            )
            self._insert_timeline_event(
                connection,
                "username_scan.completed",
                f"Completed username scan for {username}",
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
            self._insert_timeline_event(connection, "note.added", "Added note")
        return NoteRecord(text=cleaned_text, added_at=added_at)

    def record_report_rendered(self, case: str, report_format: str) -> None:
        with self.connection_for_case(case) as connection:
            self._insert_timeline_event(
                connection,
                "report.rendered",
                f"Rendered {report_format.strip().lower()} report",
            )

    def record_case_exported(self, case: str, output_path: Path) -> None:
        with self.connection_for_case(case) as connection:
            self._insert_timeline_event(
                connection,
                "case.exported",
                f"Exported case to {output_path.name}",
            )

    def record_validation_summary(
        self,
        case: str,
        status: str,
        warnings: list[str],
    ) -> ValidationSummaryRecord:
        checked_at = utc_now_iso()
        with self.connection_for_case(case) as connection:
            connection.execute(
                "DELETE FROM validation_summaries"
            )
            connection.execute(
                """
                INSERT INTO validation_summaries (status, warnings, checked_at)
                VALUES (?, ?, ?)
                """,
                (status, "\n".join(warnings), checked_at),
            )
            self._insert_timeline_event(
                connection,
                "case.validated",
                f"Validated case with status {status}",
            )
        return ValidationSummaryRecord(status=status, warnings=warnings, checked_at=checked_at)

    def snapshot(self, case: str) -> CaseSnapshot:
        with self.connection_for_case(case) as connection:
            case_row = connection.execute(
                "SELECT name, uuid, created_at FROM cases LIMIT 1"
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
                    evidence_type=row["evidence_type"],
                    path=row["path"],
                    sha256=row["sha256"],
                    created_at=row["created_at"],
                    source_url=row["source_url"],
                    note=row["note"],
                )
                for row in connection.execute(
                    """
                    SELECT evidence_id, type AS evidence_type, path, sha256,
                           created_at, source_url, note
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
            timeline = [
                TimelineEventRecord(
                    event_id=row["event_id"],
                    event_type=row["event_type"],
                    summary=row["summary"],
                    created_at=row["created_at"],
                )
                for row in connection.execute(
                    """
                    SELECT event_id, event_type, summary, created_at
                    FROM timeline_events
                    ORDER BY id
                    """
                ).fetchall()
            ]
            validation_row = connection.execute(
                """
                SELECT status, warnings, checked_at
                FROM validation_summaries
                ORDER BY id DESC
                LIMIT 1
                """
            ).fetchone()

            validation = None
            if validation_row is not None:
                warnings_text = validation_row["warnings"]
                validation = ValidationSummaryRecord(
                    status=validation_row["status"],
                    warnings=warnings_text.splitlines() if warnings_text else [],
                    checked_at=validation_row["checked_at"],
                )

        return CaseSnapshot(
            case=CaseRecord(
                name=case_row["name"],
                uuid=case_row["uuid"],
                created_at=case_row["created_at"],
                folder=str(case_path(case_row["name"], self.cases_root)),
            ),
            targets=targets,
            file_hashes=file_hashes,
            evidence=evidence,
            metadata=metadata,
            username_scans=username_scans,
            notes=notes,
            timeline=timeline,
            validation=validation,
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
                uuid TEXT UNIQUE,
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

            CREATE TABLE IF NOT EXISTS evidence (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                evidence_id TEXT NOT NULL UNIQUE,
                type TEXT NOT NULL,
                path TEXT NOT NULL,
                sha256 TEXT NOT NULL,
                created_at TEXT NOT NULL,
                source_url TEXT,
                note TEXT
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

            CREATE TABLE IF NOT EXISTS timeline_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_id TEXT NOT NULL UNIQUE,
                event_type TEXT NOT NULL,
                summary TEXT NOT NULL,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS validation_summaries (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                status TEXT NOT NULL,
                warnings TEXT NOT NULL,
                checked_at TEXT NOT NULL
            );
            """
        )
        self._migrate_schema(connection)

    def _migrate_schema(self, connection: sqlite3.Connection) -> None:
        case_columns = {
            row["name"]
            for row in connection.execute("PRAGMA table_info(cases)").fetchall()
        }
        if "uuid" not in case_columns:
            connection.execute("ALTER TABLE cases ADD COLUMN uuid TEXT")

        for row in connection.execute("SELECT id FROM cases WHERE uuid IS NULL OR uuid = ''"):
            connection.execute(
                "UPDATE cases SET uuid = ? WHERE id = ?",
                (str(uuid.uuid4()), row["id"]),
            )

        evidence_columns = {
            row["name"]
            for row in connection.execute("PRAGMA table_info(evidence)").fetchall()
        }
        if "evidence_type" in evidence_columns and "type" not in evidence_columns:
            connection.execute("ALTER TABLE evidence RENAME COLUMN evidence_type TO type")

    def _insert_evidence(
        self,
        connection: sqlite3.Connection,
        *,
        evidence_type: str,
        path: str,
        sha256: str,
        created_at: str,
        source_url: Optional[str],
        note: Optional[str],
    ) -> EvidenceRecord:
        record = EvidenceRecord(
            evidence_id=str(uuid.uuid4()),
            evidence_type=evidence_type,
            path=path,
            sha256=sha256,
            created_at=created_at,
            source_url=source_url,
            note=note,
        )
        connection.execute(
            """
            INSERT INTO evidence (evidence_id, type, path, sha256, created_at, source_url, note)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                record.evidence_id,
                record.evidence_type,
                record.path,
                record.sha256,
                record.created_at,
                record.source_url,
                record.note,
            ),
        )
        return record

    def _insert_timeline_event(
        self,
        connection: sqlite3.Connection,
        event_type: str,
        summary: str,
    ) -> TimelineEventRecord:
        record = TimelineEventRecord(
            event_id=str(uuid.uuid4()),
            event_type=event_type,
            summary=summary,
            created_at=utc_now_iso(),
        )
        connection.execute(
            """
            INSERT INTO timeline_events (event_id, event_type, summary, created_at)
            VALUES (?, ?, ?, ?)
            """,
            (record.event_id, record.event_type, record.summary, record.created_at),
        )
        return record
