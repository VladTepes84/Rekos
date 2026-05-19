"""Base interface for passive OSINT source adapters."""

from __future__ import annotations

import shutil
import re
import time
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from rekos.storage import CaseStore


@dataclass(frozen=True)
class AdapterResult:
    source: str
    target: str
    url: str
    platform: str
    confidence: str
    raw_reference: str


@dataclass(frozen=True)
class SourceRunResult:
    source: str
    target: str
    raw_output: str
    results: list[AdapterResult]
    artifacts: list[Path]
    skipped: bool = False


class BaseSourceAdapter:
    name: str = ""
    description: str = ""
    supported_target_types: tuple[str, ...] = ()
    passive_only: bool = True
    external_dependencies: tuple[str, ...] = ()

    def dependency_status(self) -> dict[str, bool]:
        return {
            dependency: shutil.which(dependency) is not None
            for dependency in self.external_dependencies
        }

    def missing_dependencies(self) -> list[str]:
        return [
            dependency
            for dependency, available in self.dependency_status().items()
            if not available
        ]

    def execute(self, case: str, target: str, store: CaseStore) -> SourceRunResult:
        missing = self.missing_dependencies()
        if missing:
            from rekos.errors import ExternalToolMissingError

            raise ExternalToolMissingError(
                f"Missing dependencies for {self.name}: {', '.join(missing)}."
            )
        raw_output = self.run(case, target)
        artifact_path = self._write_source_output(case, target, store, raw_output)
        results = self.parse_results(target, raw_output)
        store.add_adapter_results(case, results)
        store.add_timeline_event(case, "source.run", f"Ran source {self.name} for {target}")
        return SourceRunResult(
            source=self.name,
            target=target,
            raw_output=raw_output,
            results=results,
            artifacts=[artifact_path],
        )

    def run(self, case: str, target: str) -> str:
        raise NotImplementedError

    def parse_results(self, target: str, raw_output: str) -> list[AdapterResult]:
        raise NotImplementedError

    def _write_source_output(
        self,
        case: str,
        target: str,
        store: CaseStore,
        raw_output: str,
    ) -> Path:
        sources_folder = store.exports_folder(case) / "sources"
        sources_folder.mkdir(exist_ok=True)
        stem = f"{int(time.time())}-{self.name}-{_safe_export_name(target)}"
        path = sources_folder / f"{stem}.txt"
        counter = 2
        while path.exists():
            path = sources_folder / f"{stem}-{counter}.txt"
            counter += 1
        path.write_text(raw_output, encoding="utf-8")
        return path


def _safe_export_name(value: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9_.-]+", "-", value.strip()).strip(".-")
    return (cleaned or "target")[:80]
