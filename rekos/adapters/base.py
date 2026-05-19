"""Base interface for passive OSINT source adapters."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class AdapterResult:
    source: str
    target: str
    url: str
    platform: str
    confidence: str
    raw_reference: str


class BaseSourceAdapter:
    name: str = ""
    supported_target_types: tuple[str, ...] = ()

    def run(self, case: str, target: str) -> str:
        raise NotImplementedError

    def parse_results(self, target: str, raw_output: str) -> list[AdapterResult]:
        raise NotImplementedError
