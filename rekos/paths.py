"""Path helpers for local case storage."""

from __future__ import annotations

from pathlib import Path

from .errors import InvalidCaseNameError


DEFAULT_CASES_DIR_NAME = "rekos_cases"


def default_cases_root() -> Path:
    """Return the default root used for case folders."""

    return Path.home() / DEFAULT_CASES_DIR_NAME


def validate_case_name(name: str) -> str:
    """Validate a case name before using it as a folder name."""

    cleaned = name.strip()
    if not cleaned:
        raise InvalidCaseNameError("Case name cannot be empty.")
    if cleaned in {".", ".."}:
        raise InvalidCaseNameError("Case name cannot be '.' or '..'.")
    if "/" in cleaned or "\\" in cleaned:
        raise InvalidCaseNameError("Case name cannot contain path separators.")
    return cleaned


def case_path(name: str, cases_root: Path | None = None) -> Path:
    """Resolve the folder path for a case name."""

    root = cases_root or default_cases_root()
    return root / validate_case_name(name)


def database_path(name: str, cases_root: Path | None = None) -> Path:
    """Resolve the SQLite database path for a case."""

    return case_path(name, cases_root) / "rekos.db"

