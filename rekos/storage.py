"""SQLite-backed case storage."""

from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator

from .errors import CaseExistsError, CaseNotFoundError
from .models import CaseRecord, CaseSnapshot, FileHashRecord, NoteRecord, TargetRecord
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
            notes = [
                NoteRecord(text=row["text"], added_at=row["added_at"])
                for row in connection.execute(
                    "SELECT text, added_at FROM notes ORDER BY id"
                ).fetchall()
            ]

        return CaseSnapshot(
            case=CaseRecord(name=case_row["name"], created_at=case_row["created_at"]),
            targets=targets,
            file_hashes=file_hashes,
            notes=notes,
        )

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
            """
        )

