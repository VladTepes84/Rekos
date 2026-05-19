"""Typed records used by storage and report generation."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


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
class EvidenceRecord:
    evidence_id: str
    evidence_type: str
    path: str
    sha256: str
    created_at: str
    source_url: str
    note: str


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
class InvestigationProfileRecord:
    source_username: str
    profile_url: str
    confidence: str
    export_path: str
    created_at: str


@dataclass(frozen=True)
class AdapterResultRecord:
    source: str
    target: str
    url: str
    platform: str
    confidence: str
    raw_reference: str
    created_at: str


@dataclass(frozen=True)
class InvestigationSummaryRecord:
    username: str
    variant_count: int
    profile_count: int
    created_at: str
    profiles: list[InvestigationProfileRecord]


@dataclass(frozen=True)
class SnapshotRecord:
    url: str
    captured_at: str
    status_code: Optional[int]
    headers_path: str
    body_path: str
    screenshot_path: str
    evidence_id: str


@dataclass(frozen=True)
class CaseSnapshot:
    case: CaseRecord
    targets: list[TargetRecord]
    file_hashes: list[FileHashRecord]
    evidence: list[EvidenceRecord]
    metadata: list[MetadataRecord]
    username_scans: list[UsernameScanRecord]
    notes: list[NoteRecord]
    entities: list[EntityRecord]
    relationships: list[RelationshipRecord]
    graph_summary: GraphSummaryRecord
    timeline: list[TimelineEventRecord]
    investigations: list[InvestigationSummaryRecord]
    adapter_results: list[AdapterResultRecord]
    snapshots: list[SnapshotRecord]
