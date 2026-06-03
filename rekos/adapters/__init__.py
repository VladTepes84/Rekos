"""Passive OSINT source adapters."""

from .base import AdapterResult, BaseSourceAdapter, SourceRunResult
from .maigret import MaigretAdapter
from .sherlock import SherlockAdapter, SherlockUsernameAdapter
from .web_osint import (
    DnsDomainAdapter,
    EmailEnrichmentAdapter,
    EmailPassiveAdapter,
    HibpBreachAdapter,
    XposedOrNotBreachAdapter,
)
from .wmn import WmnUsernameAdapter

__all__ = [
    "AdapterResult",
    "BaseSourceAdapter",
    "DnsDomainAdapter",
    "EmailEnrichmentAdapter",
    "EmailPassiveAdapter",
    "HibpBreachAdapter",
    "MaigretAdapter",
    "SherlockAdapter",
    "SherlockUsernameAdapter",
    "SourceRunResult",
    "WmnUsernameAdapter",
    "XposedOrNotBreachAdapter",
]
