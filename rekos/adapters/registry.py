"""Registry for passive OSINT source adapters."""

from __future__ import annotations

from dataclasses import dataclass

from rekos.errors import RekosError

from .base import BaseSourceAdapter
from .http_snapshot import HttpSnapshotAdapter
from .maigret import MaigretAdapter
from .sherlock import SherlockUsernameAdapter
from .web_osint import (
    CrtshDomainAdapter,
    DnsDomainAdapter,
    EmailPassiveAdapter,
    RdapDomainAdapter,
    WaybackUrlAdapter,
    WebDomainAdapter,
)
from .wmn import WmnUsernameAdapter


class SourceNotFoundError(RekosError):
    pass


@dataclass(frozen=True)
class SourceDependencyCheck:
    source: str
    dependencies: dict[str, bool]


class SourceAdapterRegistry:
    def __init__(self, adapters: list[BaseSourceAdapter]) -> None:
        self._adapters = {adapter.name: adapter for adapter in adapters}

    def list(self) -> list[BaseSourceAdapter]:
        return [self._adapters[name] for name in sorted(self._adapters)]

    def get(self, name: str) -> BaseSourceAdapter:
        try:
            return self._adapters[name]
        except KeyError as exc:
            available = ", ".join(sorted(self._adapters))
            raise SourceNotFoundError(
                f"Unknown source '{name}'. Available sources: {available}."
            ) from exc

    def check_dependencies(self) -> list[SourceDependencyCheck]:
        return [
            SourceDependencyCheck(
                source=adapter.name,
                dependencies=adapter.dependency_status(),
            )
            for adapter in self.list()
        ]


def default_registry() -> SourceAdapterRegistry:
    return SourceAdapterRegistry(
        [
            CrtshDomainAdapter(),
            DnsDomainAdapter(),
            EmailPassiveAdapter(),
            HttpSnapshotAdapter(),
            MaigretAdapter(),
            RdapDomainAdapter(),
            SherlockUsernameAdapter(),
            WebDomainAdapter(),
            WaybackUrlAdapter(),
            WmnUsernameAdapter(),
        ]
    )
