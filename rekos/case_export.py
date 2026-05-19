"""ZIP export support for local REKOS cases."""

from __future__ import annotations

import json
import uuid
import zipfile
from dataclasses import dataclass
from pathlib import Path

from .hashfile import sha256_file
from .paths import case_path, database_path, validate_case_name
from .reporting import render_report
from .storage import CaseStore


@dataclass(frozen=True)
class ExportResult:
    output_path: Path
    file_count: int


def export_case(case: str, output_path: Path, store: CaseStore) -> ExportResult:
    cleaned_case = validate_case_name(case)
    case_folder = case_path(cleaned_case, store.cases_root)
    db_path = database_path(cleaned_case, store.cases_root)
    if not case_folder.is_dir():
        raise FileNotFoundError(f"Case folder not found: {case_folder}")
    if not db_path.is_file():
        raise FileNotFoundError(f"SQLite DB not found: {db_path}")

    reports_folder = case_folder / "reports"
    reports_folder.mkdir(exist_ok=True)
    report_path = reports_folder / "case-report.md"
    report_text = render_report(store.snapshot(cleaned_case), "md")
    _write_text_atomic(report_path, report_text)

    files = _collect_case_files(cleaned_case, case_folder, db_path, store)
    manifest_entries = []
    for archive_name, path in files:
        digest, size_bytes = sha256_file(path)
        manifest_entries.append(
            {
                "path": archive_name,
                "sha256": digest,
                "size_bytes": size_bytes,
            }
        )

    manifest = {
        "case": cleaned_case,
        "files": manifest_entries,
    }
    manifest_bytes = json.dumps(manifest, indent=2, sort_keys=True).encode("utf-8")
    manifest_sha = _sha256_bytes(manifest_bytes)
    sha_lines = [
        f"{entry['sha256']}  {entry['path']}"
        for entry in manifest_entries
    ]
    sha_lines.append(f"{manifest_sha}  manifest.json")
    manifest_sha_bytes = ("\n".join(sha_lines) + "\n").encode("utf-8")

    final_path = output_path.expanduser()
    final_path.parent.mkdir(parents=True, exist_ok=True)
    temp_path = final_path.with_name(f".{final_path.name}.{uuid.uuid4().hex}.tmp")
    try:
        with zipfile.ZipFile(temp_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            for archive_name, path in files:
                archive.write(path, archive_name)
            archive.writestr("manifest.json", manifest_bytes)
            archive.writestr("manifest.sha256", manifest_sha_bytes)
        temp_path.replace(final_path)
    except Exception:
        temp_path.unlink(missing_ok=True)
        raise

    store.record_case_exported(cleaned_case, final_path)
    return ExportResult(output_path=final_path, file_count=len(manifest_entries) + 2)


def _collect_case_files(
    case: str,
    case_folder: Path,
    db_path: Path,
    store: CaseStore,
) -> list[tuple[str, Path]]:
    files: list[tuple[str, Path]] = [("rekos.db", db_path)]
    for folder_name in ("exports", "reports"):
        folder = case_folder / folder_name
        if folder.is_dir():
            files.extend(_folder_files(case_folder, folder))

    seen = {path.resolve() for _archive_name, path in files}
    for evidence in store.snapshot(case).evidence:
        path = Path(evidence.path)
        if not path.is_absolute() or not path.is_file():
            continue
        try:
            path.relative_to(case_folder)
        except ValueError:
            continue
        resolved = path.resolve()
        if resolved in seen:
            continue
        seen.add(resolved)
        files.append((path.relative_to(case_folder).as_posix(), path))

    return sorted(files, key=lambda item: item[0])


def _folder_files(case_folder: Path, folder: Path) -> list[tuple[str, Path]]:
    collected: list[tuple[str, Path]] = []
    for path in sorted(folder.rglob("*")):
        if path.is_file():
            collected.append((path.relative_to(case_folder).as_posix(), path))
    return collected


def _write_text_atomic(path: Path, text: str) -> None:
    temp_path = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    try:
        temp_path.write_text(text, encoding="utf-8")
        temp_path.replace(path)
    except Exception:
        temp_path.unlink(missing_ok=True)
        raise


def _sha256_bytes(value: bytes) -> str:
    import hashlib

    return hashlib.sha256(value).hexdigest()
