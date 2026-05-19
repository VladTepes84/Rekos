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
class EntityRecord:
    entity_id: str
    entity_type: str
    value: str
    note: str
    created_at: str


@dataclass(frozen=True)
class RelationshipRecord:
    relationship_id: str
    source_entity_id: str
    target_entity_id: str
    relationship_type: str
    confidence: str
    note: str
    created_at: str


@dataclass(frozen=True)
class ConnectedEntityRecord:
    entity_id: str
    entity_type: str
    value: str
    connection_count: int


@dataclass(frozen=True)
class GraphSummaryRecord:
    total_entities: int
    total_relationships: int
    entity_type_counts: dict[str, int]
    most_connected: list[ConnectedEntityRecord]


@dataclass(frozen=True)
class TimelineEventRecord:
    event_type: str
    summary: str
    created_at: str


@dataclass(frozen=True)
class CaseSnapshot:
    case: CaseRecord
    targets: list[TargetRecord]
    file_hashes: list[FileHashRecord]
    metadata: list[MetadataRecord]
    username_scans: list[UsernameScanRecord]
    notes: list[NoteRecord]
    entities: list[EntityRecord]
    relationships: list[RelationshipRecord]
    graph_summary: GraphSummaryRecord
    timeline: list[TimelineEventRecord]
