"""Styled terminal banner for REKOS onboarding commands."""

from __future__ import annotations

from typing import Optional

from rich import box
from rich.align import Align
from rich.console import Group
from rich.panel import Panel
from rich.text import Text


BANNER_WIDTH = 112


def render_banner() -> Group:
    """Return a terminal-safe Rich banner without requiring external assets."""

    title = _figlet_text() or _fallback_text()
    title.stylize("bold bright_cyan")
    ready = _ready_text()
    ready.stylize("bold magenta")
    status = Text.assemble(
        ("╱╱ ◥◣", "bold blue"),
        (" ◢◤  ", "bold bright_cyan"),
        ("REKOS READY", "bold magenta"),
        ("  ◥◣ ", "bold bright_cyan"),
        ("◢◤ ╲╲", "bold blue"),
    )
    subtitle = Text(
        "TERMINAL-NATIVE // PASSIVE OSINT // LOCAL-FIRST CORRELATION",
        style="bright_cyan",
    )
    top = Panel(
        Group(
            Align.center(_title_with_eyes(title)),
            Align.center(ready),
            Align.center(status),
            Align.center(subtitle),
        ),
        border_style="bright_blue",
        box=box.DOUBLE_EDGE,
        padding=(0, 0),
        width=BANNER_WIDTH,
    )
    ready_panel = Panel(
        Text.assemble(
            ("  /\\  ", "bold magenta"),
            ("REKOS", "bold bright_cyan"),
            (" is installed and ready to use.\n      Run '", "white"),
            ("rekos quickstart", "bold magenta"),
            ("' to get started.\n      ", "white"),
            ("pipx install rekos", "bright_green"),
        ),
        border_style="magenta",
        box=box.ROUNDED,
        padding=(0, 2),
        width=BANNER_WIDTH,
    )
    quickstart_panel = Panel(
        _quickstart_table(),
        title=Text("Quick start", style="bold bright_cyan"),
        border_style="blue",
        box=box.ROUNDED,
        padding=(1, 2),
    )
    footer = Align.center(
        Text.assemble(
            ("[+] ", "bright_cyan"),
            ("Terminal-native. Passive OSINT. Local-first.", "white"),
        )
    )
    return Group(
        Align.center(top),
        Align.center(ready_panel),
        Align.center(quickstart_panel),
        footer,
    )


def _figlet_text() -> Optional[Text]:
    try:
        import pyfiglet  # type: ignore[import-not-found]
    except ImportError:
        return None
    rendered = pyfiglet.figlet_format("REKOS", font="ansi_shadow", width=86).rstrip()
    if not rendered:
        return None
    return Text(rendered)


def _fallback_text() -> Text:
    return Text(
        "\n".join(
            [
                "██████╗ ███████╗██╗  ██╗ ██████╗ ███████╗",
                "██╔══██╗██╔════╝██║ ██╔╝██╔═══██╗██╔════╝",
                "██████╔╝█████╗  █████╔╝ ██║   ██║███████╗",
                "██╔══██╗██╔══╝  ██╔═██╗ ██║   ██║╚════██║",
                "██║  ██║███████╗██║  ██╗╚██████╔╝███████║",
                "╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝",
            ]
        )
    )


def _ready_text() -> Text:
    return Text(
        "\n".join(
            [
                "   ____  _________    ____  __",
                "  / __ \\/ ____/   |  / __ \\/ /",
                " / /_/ / __/ / /| | / / / / / ",
                "/ _, _/ /___/ ___ |/ /_/ /_/  ",
                "/_/ |_/_____/_/  |_/_____(_)   ",
            ]
        )
    )


def _title_with_eyes(title: Text) -> Text:
    title_lines = title.plain.splitlines()
    left_eye = ["╱◢▰▰◣", "◢◤◉◥", "╲◥▰▰◤", "", "", ""]
    right_eye = ["◢▰▰◣╲", "◤◉◥◣", "◥▰▰◤╱", "", "", ""]
    rows: list[Text] = []
    for index, line in enumerate(title_lines):
        row = Text()
        if index < len(left_eye) and left_eye[index]:
            row.append(f"{left_eye[index]:<8}", style="bold magenta")
        else:
            row.append(" " * 8)
        row.append(" ")
        row.append(line, style="bold bright_cyan")
        row.append(" ")
        if index < len(right_eye) and right_eye[index]:
            row.append(f"{right_eye[index]:>8}", style="bold blue")
        rows.append(row)

    combined = Text()
    for index, row in enumerate(rows):
        if index:
            combined.append("\n")
        combined.append(row)
    return combined


def _quickstart_table() -> Text:
    return Text.assemble(
        ("CREATE\n", "bold bright_cyan"),
        ("  rekos new-case my_case\n\n", "bright_green"),
        ("INVESTIGATE\n", "bold magenta"),
        ("  rekos investigate username my_case username\n", "bright_green"),
        ("  rekos investigate domain my_case example.com\n\n", "bright_green"),
        ("REVIEW\n", "bold bright_cyan"),
        ("  rekos findings my_case\n", "bright_green"),
        ("  rekos findings my_case --verbose\n", "bright_green"),
        ("  rekos score my_case\n", "bright_green"),
        ("  rekos graph-summary my_case\n\n", "bright_green"),
        ("EXPORT\n", "bold magenta"),
        ("  rekos export-case my_case --output my_case.zip", "bright_green"),
    )
