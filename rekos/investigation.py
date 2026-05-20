"""Passive investigation workflows."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse, urlunparse

from .adapters import (
    AdapterResult,
    BaseSourceAdapter,
    MaigretAdapter,
    SherlockUsernameAdapter,
    WmnUsernameAdapter,
    run_adapter_sandboxed,
)
from .adapters.registry import default_registry
from .adapters.web_osint import normalize_domain
from .errors import RekosError
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
    status: str
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


@dataclass(frozen=True)
class _ProfileCandidate:
    variant: UsernameVariant
    export_path: Path
    result: AdapterResult


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
    profile_candidates: list[_ProfileCandidate] = []
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
                failures.append(SourceInvestigationFailure(source=adapter.name, status="skipped", error=message))
                store.add_timeline_event(
                    case,
                    "source.skipped",
                    f"Skipped source {adapter.name} for unsafe username variant",
                )
                continue
            if (adapter.name, run_target) in attempted_runs:
                continue
            attempted_runs.add((adapter.name, run_target))
            runtime = run_adapter_sandboxed(adapter, case, run_target)
            if runtime.status != "available":
                if runtime.status == "skipped":
                    if adapter.name in skipped_missing_sources:
                        continue
                    skipped_missing_sources.add(adapter.name)
                    skipped_count += 1
                else:
                    failed_count += 1
                message = _runtime_failure_message(adapter.name, variant.value, runtime.status, runtime.error)
                failures.append(
                    SourceInvestigationFailure(
                        source=adapter.name,
                        status=runtime.status,
                        error=message,
                    )
                )
                if runtime.raw_output or runtime.error:
                    failure_log = _failure_log(runtime.status, message, runtime.raw_output)
                    _write_export(exports_folder, _export_stem(adapter, run_target), failure_log)
                    adapter._write_source_output(case, run_target, store, failure_log)
                event_type = "source.skipped" if runtime.status == "skipped" else "source.failed"
                store.add_timeline_event(
                    case,
                    event_type,
                    f"Source {adapter.name} {runtime.status} for username variant: {message}",
                )
                continue
            export_path = _write_export(
                exports_folder,
                _export_stem(adapter, run_target),
                runtime.raw_output,
            )
            source_export_path = adapter._write_source_output(case, run_target, store, runtime.raw_output)
            for result in runtime.parsed_results:
                profile_candidates.append(
                    _ProfileCandidate(
                        variant=variant,
                        export_path=source_export_path,
                        result=_with_url(result, _normalize_profile_url(result.url)),
                    )
                )
            sources_run += 1

    normalized_results = _apply_username_confidence_model(profile_candidates)
    store.add_adapter_results(case, normalized_results)
    for candidate, result in zip(profile_candidates, normalized_results):
        key = (candidate.variant.value, result.url)
        if key in seen_profiles:
            continue
        seen_profiles.add(key)
        profiles.append(
            ProfileFinding(
                source_username=candidate.variant.value,
                profile_url=result.url,
                confidence=result.confidence,
                export_path=candidate.export_path,
                source=result.source,
                platform=result.platform,
                raw_reference=result.raw_reference,
            )
        )

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
        [(failure.source, failure.status, failure.error) for failure in failures],
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
        sources=("rdap_domain", "crtsh_domain", "wayback_url"),
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


def _apply_username_confidence_model(candidates: list[_ProfileCandidate]) -> list[AdapterResult]:
    url_sources: dict[str, set[str]] = {}
    username_sources: dict[str, set[str]] = {}
    username_urls: dict[str, set[str]] = {}
    for candidate in candidates:
        result = candidate.result
        url_key = result.url.strip().lower()
        source = result.source
        url_sources.setdefault(url_key, set()).add(source)
        profile_username = _profile_username_from_url(result.url)
        if profile_username:
            username_key = _normalize_username_key(profile_username)
            username_sources.setdefault(username_key, set()).add(source)
            username_urls.setdefault(username_key, set()).add(url_key)

    modeled: list[AdapterResult] = []
    for candidate in candidates:
        result = candidate.result
        url_key = result.url.strip().lower()
        profile_username = _profile_username_from_url(result.url)
        username_key = _normalize_username_key(profile_username)
        exact_url_sources = url_sources.get(url_key, set())
        same_username_sources = username_sources.get(username_key, set()) if username_key else set()
        same_username_urls = username_urls.get(username_key, set()) if username_key else set()
        confidence = _confidence_from_internal_score(
            candidate,
            exact_url_sources=exact_url_sources,
            same_username_sources=same_username_sources,
            same_username_urls=same_username_urls,
        )
        modeled.append(_with_confidence(result, confidence))
    return modeled


def _confidence_from_internal_score(
    candidate: _ProfileCandidate,
    *,
    exact_url_sources: set[str],
    same_username_sources: set[str],
    same_username_urls: set[str],
) -> str:
    result = candidate.result
    score = _variant_confidence_score(candidate.variant)

    if result.source in {"sherlock", "sherlock_username", "maigret", "maigret_username"}:
        score += 5
    if result.source == "wmn_username":
        score -= 30
    if _raw_reference_is_weak_template(result.raw_reference):
        score -= 15

    exact_url_confirmed = len(exact_url_sources) > 1
    same_username_different_urls = (
        not exact_url_confirmed
        and len(same_username_sources) > 1
        and len(same_username_urls) > 1
    )
    if exact_url_confirmed:
        score += 35
    elif same_username_different_urls:
        score += 12

    if result.source == "wmn_username" and not exact_url_confirmed:
        score = min(score, 44)
    if same_username_different_urls:
        score = min(score, 65)

    if score >= 75:
        return "high"
    if score >= 45:
        return "medium"
    return "low"


def _variant_confidence_score(variant: UsernameVariant) -> int:
    if variant.confidence is None:
        return 70
    if variant.confidence == "high":
        return 55
    if variant.confidence == "medium":
        return 50
    return 25


def _profile_username_from_url(url: str) -> str:
    parsed = urlparse(url)
    if not parsed.scheme or not parsed.netloc:
        return ""
    parts = [part for part in parsed.path.split("/") if part]
    if not parts:
        return ""
    return parts[-1].lstrip("@")


def _normalize_username_key(username: str) -> str:
    return username.strip().lower().lstrip("@")


def _raw_reference_is_weak_template(raw_reference: str) -> bool:
    lowered = raw_reference.lower()
    return (
        "template hit" in lowered
        or "ambiguous" in lowered
        or "redirect" in lowered
        or "blocked" in lowered
        or "rate-limit" in lowered
        or "rate limited" in lowered
    )


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


def _runtime_failure_message(source: str, target: str, status: str, error: str) -> str:
    if status == "skipped":
        if "Missing dependencies" not in error:
            return f"Missing dependencies for {source}: {error}"
        return error
    if source in {"sherlock", "sherlock_username"}:
        if status == "timeout":
            return f"{source} timed out for {target}: upstream tool timeout"
        return _clean_sherlock_failure_message(source, target)
    return error or f"{source} {status} for {target}"


def _failure_log(status: str, error: str, raw_output: str) -> str:
    sections = [f"Status: {status}", f"Error: {error}"]
    if raw_output.strip():
        sections.extend(["", "Raw output:", raw_output.strip()])
    return "\n".join(sections).rstrip() + "\n"


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
            failures.append(SourceInvestigationFailure(source=source_name, status="skipped", error=str(exc)))
            store.add_timeline_event(case, "source.skipped", f"Skipped source {source_name}: {exc}")
            continue

        missing = adapter.missing_dependencies()
        if missing:
            skipped_count += 1
            message = f"Missing dependencies: {', '.join(missing)}"
            failures.append(SourceInvestigationFailure(source=adapter.name, status="skipped", error=message))
            store.add_timeline_event(case, "source.skipped", f"Skipped source {adapter.name}: {message}")
            continue

        try:
            result = adapter.execute(case, target, store)
        except (OSError, RekosError, ValueError) as exc:
            failures.append(SourceInvestigationFailure(source=adapter.name, status="failed", error=str(exc)))
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
        [(failure.source, failure.status, failure.error) for failure in failures],
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
