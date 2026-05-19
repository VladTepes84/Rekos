"""Passive OSINT source adapters."""

from .base import AdapterResult, BaseSourceAdapter
from .maigret import MaigretAdapter
from .sherlock import SherlockAdapter

__all__ = ["AdapterResult", "BaseSourceAdapter", "MaigretAdapter", "SherlockAdapter"]
