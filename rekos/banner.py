"""Styled terminal banner for REKOS onboarding commands."""

from __future__ import annotations

from typing import Optional

from rich.align import Align
from rich.console import Group
from rich.panel import Panel
from rich.text import Text


def render_banner() -> Panel:
    """Return a terminal-safe Rich banner without requiring external assets."""

    title = _figlet_text() or _fallback_text()
    title.stylize("bold bright_cyan")
    status = Text("◥◣  ◢◤   REKOS READY   ◥◣  ◢◤", style="bold magenta")
    eyes = Text("      ◉                         ◉", style="bold blue")
    subtitle = Text(
        "PASSIVE OSINT WORKSPACE // LOCAL-FIRST // SOURCE CORRELATION",
        style="bright_cyan",
    )
    body = Group(
        Align.center(title),
        Align.center(status),
        Align.center(eyes),
        Align.center(subtitle),
    )
    return Panel(
        body,
        border_style="bright_blue",
        padding=(1, 2),
    )


def _figlet_text() -> Optional[Text]:
    try:
        import pyfiglet  # type: ignore[import-not-found]
    except ImportError:
        return None
    rendered = pyfiglet.figlet_format("REKOS", font="slant", width=100).rstrip()
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
