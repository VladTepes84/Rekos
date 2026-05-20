"""Passive OSINT source adapters."""

from .base import AdapterResult, BaseSourceAdapter, SourceRunResult
from .maigret import MaigretAdapter
from .sherlock import SherlockAdapter, SherlockUsernameAdapter
from .web_osint import DnsDomainAdapter
from .wmn import WmnUsernameAdapter

__all__ = [
    "AdapterResult",
    "BaseSourceAdapter",
    "DnsDomainAdapter",
    "MaigretAdapter",
    "SherlockAdapter",
    "SherlockUsernameAdapter",
    "SourceRunResult",
    "WmnUsernameAdapter",
]
