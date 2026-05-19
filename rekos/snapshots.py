"""Passive public URL snapshot capture."""

from __future__ import annotations

import importlib.util
import json
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional
from urllib.error import HTTPError, URLError
from urllib.parse import urldefrag, urlparse
from urllib.request import Request, urlopen

from .osint import _safe_name
from .storage import CaseStore


HTTP_TIMEOUT_SECONDS = 15
MAX_BODY_BYTES = 2 * 1024 * 1024
DUPLICATE_INTERVAL_SECONDS = 300


@dataclass(frozen=True)
class HttpCapture:
    status_code: Optional[int]
    headers: dict[str, str]
    body: str


@dataclass(frozen=True)
class SnapshotResult:
    url: str
    skipped: bool
    body_path: Optional[Path]
    headers_path: Optional[Path]
    screenshot_path: Optional[Path]
    error: Optional[str] = None


@dataclass(frozen=True)
class SnapshotInvestigationResult:
    captured: int
    skipped: int
    failed: int
    errors: list[str]


def snapshot_url(case: str, url: str, store: CaseStore) -> SnapshotResult:
    normalized_url = normalize_public_url(url)
    existing = store.recent_snapshot(case, normalized_url, DUPLICATE_INTERVAL_SECONDS)
    if existing is not None:
        return SnapshotResult(
            url=normalized_url,
            skipped=True,
            body_path=Path(existing.body_path),
            headers_path=Path(existing.headers_path),
            screenshot_path=Path(existing.screenshot_path) if existing.screenshot_path else None,
        )

    capture = fetch_public_url(normalized_url)
    snapshot_folder = store.exports_folder(case) / "snapshots"
    snapshot_folder.mkdir(exist_ok=True)
    stem = f"{int(time.time())}-{_safe_name(normalized_url)}"
    headers_path = _write_text(snapshot_folder / f"{stem}-headers.json", json.dumps(capture.headers, indent=2, sort_keys=True))
    body_path = _write_text(snapshot_folder / f"{stem}-body.html", capture.body)
    screenshot_path = capture_screenshot_if_available(normalized_url, snapshot_folder / f"{stem}-screenshot.png")

    store.add_url_snapshot(
        case,
        normalized_url,
        capture.status_code,
        headers_path,
        body_path,
        screenshot_path,
    )
    return SnapshotResult(
        url=normalized_url,
        skipped=False,
        body_path=body_path,
        headers_path=headers_path,
        screenshot_path=screenshot_path,
    )


def snapshot_investigation(case: str, store: CaseStore) -> SnapshotInvestigationResult:
    captured = 0
    skipped = 0
    failed = 0
    errors: list[str] = []
    urls: list[str] = []
    seen: set[str] = set()
    for investigation in store.investigations(case):
        for profile in investigation.profiles:
            if profile.profile_url in seen:
                continue
            seen.add(profile.profile_url)
            urls.append(profile.profile_url)

    for url in urls:
        try:
            result = snapshot_url(case, url, store)
        except Exception as exc:
            failed += 1
            errors.append(f"{url}: {exc}")
            continue
        if result.skipped:
            skipped += 1
        else:
            captured += 1
    return SnapshotInvestigationResult(captured=captured, skipped=skipped, failed=failed, errors=errors)


def normalize_public_url(url: str) -> str:
    cleaned = url.strip()
    if not cleaned:
        raise ValueError("URL cannot be empty.")
    cleaned, _fragment = urldefrag(cleaned)
    parsed = urlparse(cleaned)
    if parsed.scheme not in {"http", "https"}:
        raise ValueError("Snapshot URL scheme must be http or https.")
    if not parsed.hostname:
        raise ValueError("Snapshot URL must include a host.")
    if parsed.username or parsed.password:
        raise ValueError("Snapshot URL must not include credentials.")
    return cleaned


def fetch_public_url(url: str) -> HttpCapture:
    request = Request(
        url,
        headers={"User-Agent": "REKOS passive OSINT snapshot"},
        method="GET",
    )
    try:
        with urlopen(request, timeout=HTTP_TIMEOUT_SECONDS) as response:
            body_bytes = response.read(MAX_BODY_BYTES)
            status_code = getattr(response, "status", None)
            headers = dict(response.headers.items())
    except HTTPError as exc:
        body_bytes = exc.read(MAX_BODY_BYTES)
        status_code = exc.code
        headers = dict(exc.headers.items()) if exc.headers else {}
    except URLError as exc:
        raise RuntimeError(f"HTTP snapshot failed: {exc.reason}") from exc
    body = body_bytes.decode(_charset(headers), errors="replace")
    return HttpCapture(status_code=status_code, headers=headers, body=body)


def capture_screenshot_if_available(url: str, output_path: Path) -> Optional[Path]:
    if importlib.util.find_spec("playwright") is None:
        return None
    try:
        from playwright.sync_api import sync_playwright

        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=True)
            page = browser.new_page()
            page.goto(url, wait_until="domcontentloaded", timeout=HTTP_TIMEOUT_SECONDS * 1000)
            page.screenshot(path=str(output_path), full_page=True)
            browser.close()
    except Exception:
        return None
    return output_path if output_path.exists() else None


def _charset(headers: dict[str, str]) -> str:
    content_type = headers.get("Content-Type", headers.get("content-type", ""))
    for part in content_type.split(";"):
        key, _, value = part.strip().partition("=")
        if key.lower() == "charset" and value:
            return value
    return "utf-8"


def _write_text(path: Path, content: str) -> Path:
    path.write_text(content, encoding="utf-8")
    return path
