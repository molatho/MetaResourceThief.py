"""The ``-log`` writer.

Resource Hacker writes a UTF-16LE log **without a byte-order mark**, with CRLF
line endings.  metatwin reads it with ``Select-String -Encoding Unicode`` and
greps for ``Failed``, so both properties matter: no BOM (PowerShell infers
UTF-16LE from the first bytes) and the literal string ``Failed!`` on error.

The body mimics the original's shape closely enough that existing regexes and
eyeballs keep working:

    [23 Nov 2026, 00:12:21]

    Current Directory:
    C:\\work

    Commandline:
    "ResourceHacker" -open a.exe -action extract ...

    Open    : a.exe
    Save    : a.res
      Extracted: TEMPLATES,ACCELERATORS,0

    Success!
"""

from __future__ import annotations

import datetime as _dt
import os
import sys
from typing import List

from .resfile import ResourceEntry

_MONTHS = (
    "Jan", "Feb", "Mar", "Apr", "May", "Jun",
    "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
)

CONSOLE_TARGETS = {"CONSOLE", "CON"}
NULL_TARGETS = {"NUL"}

#: Resource Hacker's default when ``-log`` is omitted.
DEFAULT_LOG_NAME = "resourcehacker.log"


def _timestamp(now: _dt.datetime) -> str:
    return f"{now.day:02d} {_MONTHS[now.month - 1]} {now.year}, {now:%H:%M:%S}"


class ResourceLog:
    """Accumulates log lines and writes them in the original's encoding."""

    def __init__(self, target: str) -> None:
        self.target = target
        self._lines: List[str] = []
        self._finished = False

    # -- header ------------------------------------------------------------

    def banner(self, argv: List[str]) -> None:
        commandline = " ".join(argv)
        self._lines.extend(
            [
                f"[{_timestamp(_dt.datetime.now())}]",
                "",
                "Current Directory:",
                os.getcwd(),
                "",
                "Commandline:",
                commandline + " ",
                "",
            ]
        )

    def detail(self, label: str, value: str) -> None:
        """Write a ``Label   : value`` line."""
        self._lines.append(f"{label:<8}: {value}")

    def note(self, text: str) -> None:
        self._lines.append(text)

    # -- operations --------------------------------------------------------

    def extracted(self, entry: ResourceEntry) -> None:
        self._lines.append(f"  Extracted: {entry.label()}")

    def added(self, entry: ResourceEntry) -> None:
        self._lines.append(f"  Added: {entry.label()}")

    def modified(self, entry: ResourceEntry) -> None:
        self._lines.append(f"  Modified: {entry.label()}")

    def success(self) -> None:
        self._lines.extend(["", "Success!"])

    def failure(self, message: str) -> None:
        self._lines.extend(["", f"Error: {message}", "", "Failed!"])

    # -- output ------------------------------------------------------------

    def _render(self) -> str:
        return "\n".join(self._lines) + "\n"

    def flush(self) -> None:
        if self._finished:
            return
        self._finished = True
        text = self._render()

        upper = self.target.upper()
        if upper in CONSOLE_TARGETS:
            sys.stdout.write(text)
            sys.stdout.flush()
            return
        if upper in NULL_TARGETS:
            return

        directory = os.path.dirname(os.path.abspath(self.target))
        os.makedirs(directory, exist_ok=True)
        # "utf-16-le" writes no BOM, unlike "utf-16".
        with open(self.target, "w", encoding="utf-16-le", newline="\r\n") as handle:
            handle.write(text)
