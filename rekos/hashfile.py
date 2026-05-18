"""File hashing helpers."""

from __future__ import annotations

import hashlib
from pathlib import Path


def sha256_file(path: Path) -> tuple[str, int]:
    """Return the SHA-256 digest and byte size for a file."""

    hasher = hashlib.sha256()
    size_bytes = 0
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            size_bytes += len(chunk)
            hasher.update(chunk)
    return hasher.hexdigest(), size_bytes

