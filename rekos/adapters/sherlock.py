"""Sherlock passive username adapter."""

from __future__ import annotations

import re
import shutil
from urllib.parse import urlparse

from rekos.errors import ExternalToolMissingError
from rekos.osint import _run_tool

from .base import AdapterResult, BaseSourceAdapter


URL_RE = re.compile(r"https?://[^\s<>'\"]+")


class SherlockAdapter(BaseSourceAdapter):
    name = "sherlock"
    supported_target_types = ("username",)

    def run(self, case: str, target: str) -> str:
        if not shutil.which("sherlock"):
            raise ExternalToolMissingError("Missing username investigation tool: install sherlock.")
        output = _run_tool("sherlock", ["--print-found", "--", target])
        return _raw_output(output.stdout, output.stderr)

    def parse_results(self, target: str, raw_output: str) -> list[AdapterResult]:
        results: list[AdapterResult] = []
        seen: set[str] = set()
        for match in URL_RE.finditer(raw_output):
            url = match.group(0).rstrip(").,];")
            if url in seen:
                continue
            seen.add(url)
            results.append(
                AdapterResult(
                    source=self.name,
                    target=target,
                    url=url,
                    platform=_platform_from_url(url),
                    confidence="medium",
                    raw_reference=url,
                )
            )
        return results


def _platform_from_url(url: str) -> str:
    host = urlparse(url).hostname or ""
    if not host:
        return "unknown"
    parts = host.split(".")
    if len(parts) >= 2:
        return parts[-2]
    return host


def _raw_output(stdout: str, stderr: str) -> str:
    parts = [stdout.strip()]
    if stderr.strip():
        parts.extend(["", "[stderr]", stderr.strip()])
    return "\n".join(part for part in parts if part).rstrip() + "\n"
