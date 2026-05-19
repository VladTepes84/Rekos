"""Passive OSINT source adapters."""

from .base import AdapterResult, BaseSourceAdapter, SourceRunResult
from .maigret import MaigretAdapter
from .sherlock import SherlockAdapter, SherlockUsernameAdapter

__all__ = [
    "AdapterResult",
    "BaseSourceAdapter",
    "MaigretAdapter",
    "SherlockAdapter",
    "SherlockUsernameAdapter",
    "SourceRunResult",
]
