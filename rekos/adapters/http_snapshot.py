"""HTTP snapshot passive URL adapter."""

from __future__ import annotations

import json
from urllib.parse import urlparse

from rekos.snapshots import fetch_public_url, normalize_public_url, snapshot_url

from .base import AdapterResult, BaseSourceAdapter, SourceRunResult


class HttpSnapshotAdapter(BaseSourceAdapter):
    name = "http_snapshot"
    description = "Capture a public HTTP(S) URL snapshot as a local evidence artifact."
    supported_target_types = ("url",)
    passive_only = True
    external_dependencies: tuple[str, ...] = ()

    def execute(self, case: str, target: str, store) -> SourceRunResult:
        result = snapshot_url(case, target, store)
        raw_output = json.dumps(
            {
                "url": result.url,
                "skipped": result.skipped,
                "headers_path": str(result.headers_path or ""),
                "body_path": str(result.body_path or ""),
                "screenshot_path": str(result.screenshot_path or ""),
                "error": result.error or "",
            },
            indent=2,
            sort_keys=True,
        )
        adapter_result = AdapterResult(
            source=self.name,
            target=result.url,
            url=result.url,
            platform=_platform_from_url(result.url),
            confidence="high",
            raw_reference=raw_output,
        )
        source_artifact = self._write_source_output(case, result.url, store, raw_output)
        store.add_adapter_results(case, [adapter_result])
        store.add_timeline_event(case, "source.run", f"Ran source {self.name} for {result.url}")
        artifacts = [
            path
            for path in (
                source_artifact,
                result.headers_path,
                result.body_path,
                result.screenshot_path,
            )
            if path is not None
        ]
        return SourceRunResult(
            source=self.name,
            target=result.url,
            raw_output=raw_output,
            results=[adapter_result],
            artifacts=artifacts,
            skipped=result.skipped,
        )

    def run(self, case: str, target: str) -> str:
        normalized_url = normalize_public_url(target)
        capture = fetch_public_url(normalized_url)
        return json.dumps(
            {
                "url": normalized_url,
                "status_code": capture.status_code,
                "headers": capture.headers,
                "body": capture.body,
            },
            indent=2,
            sort_keys=True,
        )

    def parse_results(self, target: str, raw_output: str) -> list[AdapterResult]:
        try:
            parsed = json.loads(raw_output)
        except json.JSONDecodeError:
            parsed = {}
        url = str(parsed.get("url") or normalize_public_url(target))
        status = parsed.get("status_code", "unknown")
        return [
            AdapterResult(
                source=self.name,
                target=url,
                url=url,
                platform=_platform_from_url(url),
                confidence="high",
                raw_reference=f"HTTP status: {status}",
            )
        ]


def _platform_from_url(url: str) -> str:
    host = urlparse(url).hostname or ""
    if not host:
        return "unknown"
    parts = host.split(".")
    if len(parts) >= 2:
        return parts[-2]
    return host
