"""Local username variant generation."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class UsernameVariant:
    value: str
    confidence: Optional[str]


def username_variants(username: str) -> list[UsernameVariant]:
    original = username.strip()
    if not original:
        raise ValueError("Username cannot be empty.")

    candidates: list[UsernameVariant] = [
        UsernameVariant(original, None),
        UsernameVariant(original.lower(), "high"),
        UsernameVariant(original.replace(".", ""), "low"),
        UsernameVariant(original.replace("_", ""), "low"),
        UsernameVariant(original.replace(".", "_"), "medium"),
        UsernameVariant(original.replace("_", "."), "medium"),
        UsernameVariant(re.sub(r"[^A-Za-z0-9]+", "", original), "low"),
    ]

    seen: set[str] = set()
    deduped: list[UsernameVariant] = []
    for candidate in candidates:
        if candidate.value in seen:
            continue
        seen.add(candidate.value)
        deduped.append(candidate)
    return deduped
