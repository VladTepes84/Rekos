"""Passive OSINT source adapters."""

from .base import AdapterResult, BaseSourceAdapter, SourceRunResult
from .maigret import MaigretAdapter
from .sherlock import SherlockAdapter, SherlockUsernameAdapter
from .web_osint import DnsDomainAdapter, EmailPassiveAdapter
from .wmn import WmnUsernameAdapter

__all__ = [
    "AdapterResult",
    "BaseSourceAdapter",
    "DnsDomainAdapter",
    "EmailPassiveAdapter",
    "MaigretAdapter",
    "SherlockAdapter",
    "SherlockUsernameAdapter",
    "SourceRunResult",
    "WmnUsernameAdapter",
]
