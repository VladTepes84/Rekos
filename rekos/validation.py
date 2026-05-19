"""Validation checks for local REKOS OSINT case folders."""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from pathlib import Path

from .hashfile import sha256_file
from .paths import case_path, database_path, validate_case_name
from .storage import CaseStore


REQUIRED_TABLES = {"cases", "evidence", "timeline_events"}


@dataclass(frozen=True)
class ValidationResult:
    case: str
    status: str
    warnings: list[str]

    @property
    def ok(self) -> bool:
        return not self.warnings


def validate_case(case: str, store: CaseStore, persist: bool = True) -> ValidationResult:
    cleaned_case = validate_case_name(case)
    warnings: list[str] = []
    folder = case_path(cleaned_case, store.cases_root)
    db_path = database_path(cleaned_case, store.cases_root)

    if not folder.is_dir():
        warnings.append(f"Case folder missing: {folder}")
        return _finish(cleaned_case, warnings, store, persist=False)

    if not db_path.is_file():
        warnings.append(f"SQLite DB missing: {db_path}")
        return _finish(cleaned_case, warnings, store, persist=False)

    try:
        with sqlite3.connect(db_path) as connection:
            connection.row_factory = sqlite3.Row
            tables = {
                row["name"]
                for row in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type = 'table'"
                ).fetchall()
            }
            for table in sorted(REQUIRED_TABLES - tables):
                warnings.append(f"Required table missing: {table}")

            if "cases" in tables:
                row = connection.execute(
                    "SELECT uuid FROM cases LIMIT 1"
                ).fetchone()
                if row is None or not str(row["uuid"] or "").strip():
                    warnings.append("Case UUID missing")

            if "evidence" in tables:
                _validate_evidence_files(connection, warnings)
    except sqlite3.Error as exc:
        warnings.append(f"SQLite validation failed: {exc}")

    return _finish(cleaned_case, warnings, store, persist=persist)


def _validate_evidence_files(
    connection: sqlite3.Connection,
    warnings: list[str],
) -> None:
    rows = connection.execute(
        "SELECT evidence_id, path, sha256 FROM evidence ORDER BY id"
    ).fetchall()
    for row in rows:
        evidence_id = row["evidence_id"]
        path = Path(row["path"])
        if not path.is_absolute():
            continue
        if not path.exists():
            warnings.append(f"Evidence file missing: {evidence_id} ({path})")
            continue
        if not path.is_file():
            warnings.append(f"Evidence path is not a file: {evidence_id} ({path})")
            continue
        digest, _size_bytes = sha256_file(path)
        if digest != row["sha256"]:
            warnings.append(f"Evidence SHA256 mismatch: {evidence_id} ({path})")


def _finish(
    case: str,
    warnings: list[str],
    store: CaseStore,
    persist: bool,
) -> ValidationResult:
    status = "ok" if not warnings else "warning"
    if persist:
        store.record_validation_summary(case, status, warnings)
    return ValidationResult(case=case, status=status, warnings=warnings)
