"""Passive OSINT subprocess wrappers and export handling."""

from __future__ import annotations

import re
import shutil
import subprocess
import uuid
from dataclasses import dataclass
from pathlib import Path

from .errors import ExternalToolExecutionError, ExternalToolMissingError, ExternalToolTimeoutError
from .storage import CaseStore


TOOL_TIMEOUT_SECONDS = 120


@dataclass(frozen=True)
class CommandOutput:
    tool: str
    stdout: str
    stderr: str


def collect_metadata(case: str, file_path: Path, store: CaseStore) -> tuple[list[str], Path]:
    source = file_path.expanduser()
    if not source.is_file():
        raise FileNotFoundError(f"File not found: {source}")
    exports_folder = store.exports_folder(case)

    tools = [tool for tool in ("exiftool", "mediainfo") if shutil.which(tool)]
    if not tools:
        raise ExternalToolMissingError("Missing metadata tool: install exiftool or mediainfo.")

    outputs = [_run_tool(tool, [str(source.resolve())]) for tool in tools]
    raw_output = _format_outputs(outputs)
    export_path = _write_export(
        exports_folder,
        f"metadata-{_safe_name(source.name)}",
        raw_output,
    )
    store.add_metadata_result(case, source.resolve(), tools, raw_output, export_path)
    return tools, export_path


def scan_username(case: str, username: str, store: CaseStore) -> Path:
    cleaned_username = username.strip()
    if not cleaned_username:
        raise ValueError("Username cannot be empty.")
    exports_folder = store.exports_folder(case)
    if not shutil.which("sherlock"):
        raise ExternalToolMissingError("Missing username scan tool: install sherlock.")

    output = _run_tool("sherlock", ["--print-found", "--", cleaned_username])
    raw_output = _format_outputs([output])
    export_path = _write_export(
        exports_folder,
        f"username-scan-{_safe_name(cleaned_username)}",
        raw_output,
    )
    store.add_username_scan(case, cleaned_username, raw_output, export_path)
    return export_path


def _run_tool(tool: str, args: list[str]) -> CommandOutput:
    executable = shutil.which(tool)
    if executable is None:
        raise ExternalToolMissingError(f"Missing required tool: {tool}.")
    return _run_command([executable, *args], tool)


def _run_command(command: list[str], tool: str) -> CommandOutput:
    try:
        completed = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            timeout=TOOL_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired as exc:
        raise ExternalToolTimeoutError(
            f"{tool} timed out after {TOOL_TIMEOUT_SECONDS} seconds."
        ) from exc
    stdout = completed.stdout.strip()
    stderr = completed.stderr.strip()
    if completed.returncode != 0:
        details = stderr or stdout or f"exit code {completed.returncode}"
        raise ExternalToolExecutionError(f"{tool} failed: {details}")
    return CommandOutput(tool=tool, stdout=stdout, stderr=stderr)


def _format_outputs(outputs: list[CommandOutput]) -> str:
    sections: list[str] = []
    for output in outputs:
        sections.append(f"## {output.tool}")
        sections.append("")
        sections.append(output.stdout or "(no stdout)")
        if output.stderr:
            sections.append("")
            sections.append("[stderr]")
            sections.append(output.stderr)
        sections.append("")
    return "\n".join(sections).rstrip() + "\n"


def _write_export(exports_folder: Path, stem: str, raw_output: str) -> Path:
    export_path = exports_folder / f"{stem}.txt"
    counter = 2
    while export_path.exists():
        export_path = exports_folder / f"{stem}-{counter}.txt"
        counter += 1
    temp_path = exports_folder / f".{export_path.name}.{uuid.uuid4().hex}.tmp"
    try:
        temp_path.write_text(raw_output, encoding="utf-8")
        temp_path.replace(export_path)
    except Exception:
        temp_path.unlink(missing_ok=True)
        raise
    return export_path


def _safe_name(value: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9_.-]+", "-", value.strip()).strip(".-")
    return (cleaned or "result")[:80]
