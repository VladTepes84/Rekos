"""Command-line interface for REKOS."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Sequence

from rich.console import Console

from .errors import RekosError
from .hashfile import sha256_file
from .osint import collect_metadata, scan_username
from .reporting import render_report
from .storage import CaseStore


console = Console()
error_console = Console(stderr=True)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="rekos", description="Local defensive case-management CLI")
    subparsers = parser.add_subparsers(dest="command", required=True)

    new_case = subparsers.add_parser("new-case", help="Create a new local case")
    new_case.add_argument("name")

    add_target = subparsers.add_parser("add-target", help="Add a bounded case target")
    add_target.add_argument("case")
    add_target.add_argument("--type", required=True, dest="target_type")
    add_target.add_argument("--value", required=True)

    hash_file = subparsers.add_parser("hash-file", help="Hash a file and store the result in a case")
    hash_file.add_argument("case")
    hash_file.add_argument("file")

    metadata = subparsers.add_parser("metadata", help="Collect passive file metadata")
    metadata.add_argument("case")
    metadata.add_argument("file")

    username_scan = subparsers.add_parser("username-scan", help="Run a passive username scan")
    username_scan.add_argument("case")
    username_scan.add_argument("username")

    add_note = subparsers.add_parser("add-note", help="Add a note to a case")
    add_note.add_argument("case")
    add_note.add_argument("text")

    report = subparsers.add_parser("report", help="Render a case report")
    report.add_argument("case")
    report.add_argument("--format", default="md", choices=["md"])

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    store = CaseStore()

    try:
        if args.command == "new-case":
            folder = store.create_case(args.name)
            console.print(f"[green]Created case[/green] {args.name} at {folder}")
            return 0

        if args.command == "add-target":
            target = store.add_target(args.case, args.target_type, args.value)
            console.print(f"[green]Added target[/green] {target.target_type}: {target.value}")
            return 0

        if args.command == "hash-file":
            source = Path(args.file).expanduser()
            if not source.is_file():
                raise FileNotFoundError(f"File not found: {source}")
            digest, size_bytes = sha256_file(source)
            file_hash = store.add_file_hash(args.case, source.resolve(), digest, size_bytes)
            console.print(f"[green]Hashed file[/green] {file_hash.path}")
            console.print(f"SHA-256: [bold]{file_hash.sha256}[/bold]")
            return 0

        if args.command == "metadata":
            tools, export_path = collect_metadata(args.case, Path(args.file), store)
            console.print(f"[green]Collected metadata[/green] with {', '.join(tools)}")
            console.print(f"Export: {export_path}")
            return 0

        if args.command == "username-scan":
            export_path = scan_username(args.case, args.username, store)
            console.print(f"[green]Completed username scan[/green] {args.username}")
            console.print(f"Export: {export_path}")
            return 0

        if args.command == "add-note":
            note = store.add_note(args.case, args.text)
            console.print(f"[green]Added note[/green] ({note.added_at})")
            return 0

        if args.command == "report":
            report_text = render_report(store.snapshot(args.case), args.format)
            console.print(report_text, markup=False)
            return 0

    except (OSError, RekosError, ValueError) as exc:
        error_console.print(f"[red]Error:[/red] {exc}")
        return 1

    parser.error(f"Unhandled command: {args.command}")
    return 2


def console_main() -> None:
    sys.exit(main())


if __name__ == "__main__":
    console_main()
