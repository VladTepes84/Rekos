"""Passive investigation workflows."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse, urlunparse

from .adapters import AdapterResult, BaseSourceAdapter, MaigretAdapter, SherlockUsernameAdapter, WmnUsernameAdapter
from .adapters.registry import default_registry
from .adapters.web_osint import normalize_domain
from .errors import ExternalToolExecutionError, ExternalToolMissingError, RekosError
from .osint import _safe_name, _write_export
from .snapshots import normalize_public_url
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
class SourceInvestigationFailure:
    source: str
    error: str


@dataclass(frozen=True)
class UsernameInvestigationResult:
    username: str
    variants: list[UsernameVariant]
    profiles: list[ProfileFinding]
    failures: list[SourceInvestigationFailure]


@dataclass(frozen=True)
class MultiSourceInvestigationResult:
    target_type: str
    target: str
    sources_run: int
    results: int
    skipped: int
    failed: int
    failures: list[SourceInvestigationFailure]


def investigate_username(
    case: str,
    username: str,
    store: CaseStore,
) -> UsernameInvestigationResult:
    variants = username_variants(username)
    exports_folder = store.exports_folder(case)
    adapters: list[BaseSourceAdapter] = [SherlockUsernameAdapter(), MaigretAdapter(), WmnUsernameAdapter()]

    profiles: list[ProfileFinding] = []
    seen_profiles: set[tuple[str, str]] = set()
    attempted_runs: set[tuple[str, str]] = set()
    sources_run = 0
    skipped_count = 0
    failed_count = 0
    failures: list[SourceInvestigationFailure] = []
    skipped_missing_sources: set[str] = set()
    for variant in variants:
        for adapter in adapters:
            run_target = variant.value
            if adapter.name == "sherlock_username" and not _is_safe_sherlock_username(run_target):
                skipped_count += 1
                message = _clean_sherlock_failure_message(adapter.name, run_target)
                failures.append(SourceInvestigationFailure(source=adapter.name, error=message))
                store.add_timeline_event(
                    case,
                    "source.skipped",
                    f"Skipped source {adapter.name} for unsafe username variant",
                )
                continue
            if (adapter.name, run_target) in attempted_runs:
                continue
            attempted_runs.add((adapter.name, run_target))
            try:
                raw_output = adapter.run(case, run_target)
            except ExternalToolMissingError as exc:
                if adapter.name == "sherlock_username":
                    raise
                if adapter.name in skipped_missing_sources:
                    continue
                skipped_missing_sources.add(adapter.name)
                skipped_count += 1
                message = f"Missing dependencies for {adapter.name}: {exc}"
                failures.append(SourceInvestigationFailure(source=adapter.name, error=message))
                store.add_timeline_event(
                    case,
                    "source.skipped",
                    f"Skipped source {adapter.name}: {exc}",
                )
                continue
            except ExternalToolExecutionError as exc:
                failed_count += 1
                if adapter.name == "maigret_username":
                    message = str(exc)
                else:
                    message = _clean_sherlock_failure_message(adapter.name, variant.value)
                failures.append(SourceInvestigationFailure(source=adapter.name, error=message))
                store.add_timeline_event(
                    case,
                    "source.failed",
                    f"Source {adapter.name} failed for username variant: {message}",
                )
                continue
            export_path = _write_export(
                exports_folder,
                _export_stem(adapter, run_target),
                raw_output,
            )
            source_export_path = adapter._write_source_output(case, run_target, store, raw_output)
            adapter_results = [
                _with_confidence(result, profile_confidence(variant))
                for result in adapter.parse_results(run_target, raw_output)
            ]
            normalized_results = [
                _with_url(result, _normalize_profile_url(result.url))
                for result in adapter_results
            ]
            store.add_adapter_results(case, normalized_results)
            for result in adapter_results:
                normalized_url = _normalize_profile_url(result.url)
                key = (variant.value, normalized_url)
                if key in seen_profiles:
                    continue
                seen_profiles.add(key)
                profiles.append(
                    ProfileFinding(
                        source_username=variant.value,
                        profile_url=normalized_url,
                        confidence=result.confidence,
                        export_path=source_export_path,
                        source=result.source,
                        platform=result.platform,
                        raw_reference=result.raw_reference,
                    )
                )
            sources_run += 1

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
    store.add_source_investigation(
        case,
        "username",
        variants[0].value,
        sources_run,
        len(profiles),
        skipped_count,
        failed_count,
        [(failure.source, failure.error) for failure in failures],
    )
    return UsernameInvestigationResult(
        username=variants[0].value,
        variants=variants,
        profiles=profiles,
        failures=failures,
    )


def investigate_domain(case: str, domain: str, store: CaseStore) -> MultiSourceInvestigationResult:
    normalized_domain = normalize_domain(domain)
    return _investigate_sources(
        case=case,
        target_type="domain",
        target=normalized_domain,
        sources=("rdap_domain", "dns_domain"),
        entity_type="domain",
        store=store,
    )


def investigate_url(case: str, url: str, store: CaseStore) -> MultiSourceInvestigationResult:
    normalized_url = normalize_public_url(url)
    return _investigate_sources(
        case=case,
        target_type="url",
        target=normalized_url,
        sources=("http_snapshot", "wayback_url"),
        entity_type="url",
        store=store,
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


def _with_url(result: AdapterResult, url: str) -> AdapterResult:
    return AdapterResult(
        source=result.source,
        target=result.target,
        url=url,
        platform=result.platform,
        confidence=result.confidence,
        raw_reference=result.raw_reference,
    )


def _export_stem(adapter: BaseSourceAdapter, username: str) -> str:
    safe_username = _safe_name(username)
    if adapter.name in {"sherlock", "sherlock_username"}:
        return f"investigate-username-{safe_username}"
    return f"investigate-{adapter.name}-{safe_username}"


_SHERLOCK_SAFE_USERNAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,79}$")


def _is_safe_sherlock_username(username: str) -> bool:
    value = username.strip()
    return (
        value == username
        and bool(_SHERLOCK_SAFE_USERNAME_RE.fullmatch(value))
        and ".." not in value
        and not value.endswith(".")
    )


def _clean_sherlock_failure_message(source: str, target: str) -> str:
    if source in {"sherlock", "sherlock_username"}:
        return f"{source} failed for {target}: invalid generated site URL / upstream tool error"
    return f"{source} failed for {target}: upstream tool error"


def _normalize_profile_url(url: str) -> str:
    parsed = urlparse(url.strip())
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return url.strip()
    path = parsed.path.rstrip("/") or ""
    return urlunparse(
        (
            parsed.scheme.lower(),
            parsed.netloc.lower(),
            path,
            "",
            parsed.query,
            "",
        )
    )


def _investigate_sources(
    *,
    case: str,
    target_type: str,
    target: str,
    sources: tuple[str, ...],
    entity_type: str,
    store: CaseStore,
) -> MultiSourceInvestigationResult:
    registry = default_registry()
    store.ensure_entity(case, entity_type, target, f"{target_type} investigation target")
    store.add_timeline_event(case, "investigation.started", f"Started {target_type} investigation for {target}")

    sources_run = 0
    result_count = 0
    skipped_count = 0
    failures: list[SourceInvestigationFailure] = []
    for source_name in sources:
        try:
            adapter = registry.get(source_name)
        except RekosError as exc:
            skipped_count += 1
            failures.append(SourceInvestigationFailure(source=source_name, error=str(exc)))
            store.add_timeline_event(case, "source.skipped", f"Skipped source {source_name}: {exc}")
            continue

        missing = adapter.missing_dependencies()
        if missing:
            skipped_count += 1
            message = f"Missing dependencies: {', '.join(missing)}"
            failures.append(SourceInvestigationFailure(source=adapter.name, error=message))
            store.add_timeline_event(case, "source.skipped", f"Skipped source {adapter.name}: {message}")
            continue

        try:
            result = adapter.execute(case, target, store)
        except (OSError, RekosError, ValueError) as exc:
            failures.append(SourceInvestigationFailure(source=adapter.name, error=str(exc)))
            store.add_timeline_event(case, "source.failed", f"Source {adapter.name} failed: {exc}")
            continue
        sources_run += 1
        result_count += len(result.results)

    failed_count = len(failures) - skipped_count
    store.add_source_investigation(
        case,
        target_type,
        target,
        sources_run,
        result_count,
        skipped_count,
        failed_count,
        [(failure.source, failure.error) for failure in failures],
    )
    return MultiSourceInvestigationResult(
        target_type=target_type,
        target=target,
        sources_run=sources_run,
        results=result_count,
        skipped=skipped_count,
        failed=failed_count,
        failures=failures,
    )
