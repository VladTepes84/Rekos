"""Passive username investigation workflow."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from .adapters import AdapterResult, BaseSourceAdapter, MaigretAdapter, SherlockUsernameAdapter
from .errors import ExternalToolMissingError
from .osint import _safe_name, _write_export
from .storage import CaseStore
from .usernames import UsernameVariant, username_variants


@dataclass(frozen=True)
class ProfileFinding:
    source_username: str
    profile_url: str
    confidence: str
    export_path: Path
    source: str
    platform: str
    raw_reference: str


@dataclass(frozen=True)
class UsernameInvestigationResult:
    username: str
    variants: list[UsernameVariant]
    profiles: list[ProfileFinding]


def investigate_username(
    case: str,
    username: str,
    store: CaseStore,
) -> UsernameInvestigationResult:
    variants = username_variants(username)
    exports_folder = store.exports_folder(case)
    adapters: list[BaseSourceAdapter] = [SherlockUsernameAdapter(), MaigretAdapter()]

    profiles: list[ProfileFinding] = []
    seen_profiles: set[tuple[str, str]] = set()
    for variant in variants:
        for adapter in adapters:
            try:
                raw_output = adapter.run(case, variant.value)
            except ExternalToolMissingError:
                if adapter.name == "sherlock_username":
                    raise
                continue
            export_path = _write_export(
                exports_folder,
                _export_stem(adapter, variant.value),
                raw_output,
            )
            adapter_results = [
                _with_confidence(result, profile_confidence(variant))
                for result in adapter.parse_results(variant.value, raw_output)
            ]
            new_adapter_results: list[AdapterResult] = []
            for result in adapter_results:
                key = (variant.value, result.url)
                if key in seen_profiles:
                    continue
                seen_profiles.add(key)
                new_adapter_results.append(result)
                profiles.append(
                    ProfileFinding(
                        source_username=variant.value,
                        profile_url=result.url,
                        confidence=result.confidence,
                        export_path=export_path,
                        source=result.source,
                        platform=result.platform,
                        raw_reference=result.raw_reference,
                    )
                )
            store.add_adapter_results(case, new_adapter_results)

    store.add_username_investigation(
        case,
        variants[0].value,
        variants,
        [
            {
                "source_username": profile.source_username,
                "profile_url": profile.profile_url,
                "confidence": profile.confidence,
                "export_path": str(profile.export_path),
                "source": profile.source,
                "platform": profile.platform,
                "raw_reference": profile.raw_reference,
            }
            for profile in profiles
        ],
    )
    return UsernameInvestigationResult(
        username=variants[0].value,
        variants=variants,
        profiles=profiles,
    )


def profile_confidence(variant: UsernameVariant) -> str:
    if variant.confidence is None:
        return "high"
    if variant.confidence in {"high", "medium"}:
        return "medium"
    return "low"


def _with_confidence(result: AdapterResult, confidence: str) -> AdapterResult:
    return AdapterResult(
        source=result.source,
        target=result.target,
        url=result.url,
        platform=result.platform,
        confidence=confidence,
        raw_reference=result.raw_reference,
    )


def _export_stem(adapter: BaseSourceAdapter, username: str) -> str:
    safe_username = _safe_name(username)
    if adapter.name in {"sherlock", "sherlock_username"}:
        return f"investigate-username-{safe_username}"
    return f"investigate-{adapter.name}-{safe_username}"
