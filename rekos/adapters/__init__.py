"""Passive OSINT source adapters."""

from .base import AdapterResult, AdapterRuntimeResult, BaseSourceAdapter, SourceRunResult, run_adapter_sandboxed
from .maigret import MaigretAdapter
from .sherlock import SherlockAdapter, SherlockUsernameAdapter
from .wmn import WmnUsernameAdapter

__all__ = [
    "AdapterResult",
    "AdapterRuntimeResult",
    "BaseSourceAdapter",
    "MaigretAdapter",
    "SherlockAdapter",
    "SherlockUsernameAdapter",
    "SourceRunResult",
    "WmnUsernameAdapter",
    "run_adapter_sandboxed",
]
