"""Typed records used by storage and report generation."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class CaseRecord:
    name: str
    created_at: str


@dataclass(frozen=True)
class TargetRecord:
    target_type: str
    value: str
    added_at: str


@dataclass(frozen=True)
class FileHashRecord:
    path: str
    sha256: str
    size_bytes: int
    added_at: str


@dataclass(frozen=True)
class MetadataRecord:
    path: str
    tools: str
    raw_output: str
    export_path: str
    added_at: str


@dataclass(frozen=True)
class UsernameScanRecord:
    username: str
    raw_output: str
    export_path: str
    added_at: str


@dataclass(frozen=True)
class NoteRecord:
    text: str
    added_at: str


@dataclass(frozen=True)
class CaseSnapshot:
    case: CaseRecord
    targets: list[TargetRecord]
    file_hashes: list[FileHashRecord]
    metadata: list[MetadataRecord]
    username_scans: list[UsernameScanRecord]
    notes: list[NoteRecord]
