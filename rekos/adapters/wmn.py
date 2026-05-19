"""WhatsMyName-style passive username adapter."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlparse
from urllib.request import Request, urlopen

from .base import AdapterResult, BaseSourceAdapter
from .web_osint import USER_AGENT


WMN_TIMEOUT_SECONDS = 10
SOURCE_LIST_PATH = Path(__file__).with_name("wmn_sources.json")


@dataclass(frozen=True)
class WmnSource:
    platform: str
    url_template: str


class WmnUsernameAdapter(BaseSourceAdapter):
    name = "wmn_username"
    description = "Check public profile URL templates from a local username source list."
    supported_target_types = ("username",)
    passive_only = True
    external_dependencies: tuple[str, ...] = ()

    def run(self, case: str, target: str) -> str:
        username = target.strip()
        if not username:
            raise ValueError("Username target cannot be empty.")
        encoded_username = quote(username, safe="")
        results: list[dict[str, object]] = []
        for source in _load_sources():
            url = source.url_template.format(username=encoded_username)
            status_code: int | None = None
            error = ""
            try:
                request = Request(
                    url,
                    headers={"User-Agent": USER_AGENT},
                    method="HEAD",
                )
                with urlopen(request, timeout=WMN_TIMEOUT_SECONDS) as response:
                    status_code = response.status
            except HTTPError as exc:
                status_code = exc.code
                error = str(exc.reason or exc)
            except (OSError, TimeoutError, URLError) as exc:
                error = str(exc)
            results.append(
                {
                    "platform": source.platform,
                    "url": url,
                    "status_code": status_code,
                    "hit": _is_hit(status_code),
                    "error": error,
                }
            )
        return json.dumps(
            {
                "source": self.name,
                "target": username,
                "results": results,
            },
            indent=2,
            sort_keys=True,
        )

    def parse_results(self, target: str, raw_output: str) -> list[AdapterResult]:
        try:
            parsed = json.loads(raw_output)
        except json.JSONDecodeError:
            return []
        results: list[AdapterResult] = []
        seen: set[str] = set()
        for item in parsed.get("results", []):
            if not isinstance(item, dict) or not item.get("hit"):
                continue
            url = str(item.get("url") or "").strip()
            if not _is_http_url(url) or url in seen:
                continue
            seen.add(url)
            platform = str(item.get("platform") or _platform_from_url(url)).strip().lower()
            results.append(
                AdapterResult(
                    source=self.name,
                    target=str(parsed.get("target") or target),
                    url=url,
                    platform=platform,
                    confidence="medium",
                    raw_reference=f"HTTP status: {item.get('status_code', 'unknown')}",
                )
            )
        return results


def _load_sources() -> list[WmnSource]:
    payload = json.loads(SOURCE_LIST_PATH.read_text(encoding="utf-8"))
    return [
        WmnSource(
            platform=str(item["platform"]),
            url_template=str(item["url_template"]),
        )
        for item in payload
    ]


def _is_hit(status_code: int | None) -> bool:
    return status_code is not None and 200 <= status_code < 400


def _is_http_url(value: str) -> bool:
    return urlparse(value).scheme in {"http", "https"}


def _platform_from_url(url: str) -> str:
    host = urlparse(url).hostname or ""
    parts = host.split(".")
    if len(parts) >= 2:
        return parts[-2]
    return host or "unknown"
