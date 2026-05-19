"""Maigret passive username adapter."""

from __future__ import annotations

import importlib.util
import os
import re
import shutil
import sys
from pathlib import Path
from urllib.parse import urlparse

from rekos.errors import ExternalToolMissingError
from rekos.osint import _run_command

from .base import AdapterResult, BaseSourceAdapter


URL_RE = re.compile(r"https?://[^\s<>'\"]+")
MAIGRET_EXECUTABLE_NAMES = ("maigret", "maigret.py")


class MaigretAdapter(BaseSourceAdapter):
    name = "maigret_username"
    description = "Run Maigret against a username and parse public profile URLs."
    supported_target_types = ("username",)
    passive_only = True
    external_dependencies = ("maigret",)

    def dependency_status(self) -> dict[str, bool]:
        return {"maigret": _resolve_maigret_command() is not None}

    def run(self, case: str, target: str) -> str:
        command = _resolve_maigret_command()
        if command is None:
            raise ExternalToolMissingError("Missing username investigation tool: install maigret.")
        output = _run_command([*command, "--print-found", "--", target], "maigret")
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


def _resolve_maigret_command() -> list[str] | None:
    for executable_name in MAIGRET_EXECUTABLE_NAMES:
        executable = shutil.which(executable_name)
        if executable:
            return [executable]

    python_bin = Path(sys.executable).resolve().parent
    for executable_name in MAIGRET_EXECUTABLE_NAMES:
        candidate = python_bin / executable_name
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return [str(candidate)]

    if _module_runner_available("maigret"):
        return [sys.executable, "-m", "maigret"]
    return None


def _module_runner_available(module_name: str) -> bool:
    try:
        return importlib.util.find_spec(f"{module_name}.__main__") is not None
    except (ImportError, AttributeError, ValueError):
        return False
