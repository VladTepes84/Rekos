"""Local case export helpers."""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
import zipfile
from pathlib import Path

from .paths import case_path, validate_case_name
from .storage import CaseStore


def export_case(case: str, output_path: Path, store: CaseStore) -> Path:
    case_name = validate_case_name(case)
    root = case_path(case_name, store.cases_root)
    if not root.is_dir():
        raise FileNotFoundError(f"Case not found: {case_name}")

    output = output_path.expanduser()
    output.parent.mkdir(parents=True, exist_ok=True)
    files = sorted(path for path in root.rglob("*") if path.is_file())
    manifest: dict[str, str] = {}
    with tempfile.NamedTemporaryFile(
        prefix=f".{output.name}.",
        suffix=".tmp",
        dir=str(output.parent),
        delete=False,
    ) as handle:
        temp_path = Path(handle.name)

    try:
        with zipfile.ZipFile(temp_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            for path in files:
                relative = path.relative_to(root).as_posix()
                archive.write(path, f"{case_name}/{relative}")
                manifest[f"{case_name}/{relative}"] = _sha256(path)
            manifest_bytes = json.dumps(
                {
                    "case": case_name,
                    "files": manifest,
                },
                indent=2,
                sort_keys=True,
            ).encode("utf-8")
            archive.writestr(f"{case_name}/manifest.json", manifest_bytes)
            archive.writestr(
                f"{case_name}/manifest.sha256",
                hashlib.sha256(manifest_bytes).hexdigest() + "  manifest.json\n",
            )
        os.replace(temp_path, output)
    except Exception:
        temp_path.unlink(missing_ok=True)
        raise
    return output


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()
