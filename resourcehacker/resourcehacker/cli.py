"""Command-line front end.

Only the two actions metatwin needs are implemented — ``extract`` and
``addoverwrite`` — plus the switch parsing, mask handling and log contract that
surround them.  Anything else exits non-zero with a clear message rather than
silently doing the wrong thing.
"""

from __future__ import annotations

import sys
from typing import Dict, List, Optional

from .logfile import DEFAULT_LOG_NAME, ResourceLog
from .mask import MaskError, parse_mask
from .pelayer import OVERWRITE, PEError, PEImage, REPLACE
from .resfile import ResError, read_file, write_file

USAGE = """\
Usage: ResourceHacker -open FILE -save FILE -action ACTION [options]

  -open     PE file to read or modify
  -save     output file (never the same as -open)
  -action   extract | addoverwrite | replace
  -mask     Type,Name,Language  (three comma-separated fields; empty = any)
  -resource file whose resources are added to the opened file
  -log      filename, CONSOLE or NUL (default: resourcehacker.log)
  -help     show this text

Actions:
  extract       write the resources matched by -mask to a .res file
  addoverwrite  merge -resource into the opened file, overwriting collisions
  replace       discard the opened file's resources and install -resource
                verbatim; this is the cloning action
"""

#: Switches that must be followed by a value.
_VALUE_REQUIRED = frozenset({"open", "save", "resource", "action", "mask", "log", "script"})
#: Switches whose value is optional.
_VALUE_OPTIONAL = frozenset({"help"})
_SWITCHES = _VALUE_REQUIRED | _VALUE_OPTIONAL

#: Resource Hacker exits 0xFFFFFFFF on failure.
_EXIT_FAILURE = -1


class UsageError(ValueError):
    """Raised for malformed command lines."""


def _resolve(name: str) -> str:
    """Resolve a switch name, honouring unambiguous abbreviations."""
    if name in _SWITCHES:
        return name
    matches = sorted(switch for switch in _SWITCHES if switch.startswith(name))
    if len(matches) == 1:
        return matches[0]
    if not matches:
        raise UsageError(f"unknown switch -{name}")
    raise UsageError(
        f"ambiguous switch -{name} (matches {', '.join('-' + m for m in matches)})"
    )


def parse_switches(argv: List[str]) -> Dict[str, Optional[str]]:
    """Turn ``['-open', 'a.exe', '-action', 'extract']`` into a dict."""
    options: Dict[str, Optional[str]] = {}
    index = 0
    while index < len(argv):
        token = argv[index]
        if not token.startswith("-") or token == "-":
            raise UsageError(f"unexpected argument {token!r}; switches start with '-'")
        name = _resolve(token.lstrip("-").lower())
        index += 1
        if name in _VALUE_OPTIONAL:
            if index < len(argv) and not argv[index].startswith("-"):
                options[name] = argv[index]
                index += 1
            else:
                options[name] = None
            continue
        if index >= len(argv):
            raise UsageError(f"switch -{name} requires a value")
        options[name] = argv[index]
        index += 1
    return options


def _require(options: Dict[str, Optional[str]], *names: str) -> None:
    missing = [f"-{name}" for name in names if not options.get(name)]
    if missing:
        raise UsageError(f"missing required {', '.join(missing)}")


def _extract(options: Dict[str, Optional[str]], log: ResourceLog) -> None:
    _require(options, "open", "save")
    open_path = options["open"]
    save_path = options["save"]
    mask = parse_mask(options.get("mask"))

    log.detail("Open", open_path)
    log.detail("Save", save_path)
    log.detail("Mask", options.get("mask") or "")

    with PEImage(open_path) as image:
        entries = image.entries()

    selected = [
        entry
        for entry in entries
        if mask.matches(entry.type_id, entry.name_id, entry.language)
    ]
    if not selected:
        # Resource Hacker writes no file when nothing matches, and still
        # reports success.  Reproduced deliberately: metatwin then fails at its
        # merge step, exactly as it would with the original.
        log.note("  No resources matched the mask.")
        return

    write_file(save_path, selected)
    for entry in selected:
        log.extracted(entry)


def _apply_resources(
    options: Dict[str, Optional[str]], log: ResourceLog, mode: str
) -> None:
    _require(options, "open", "save", "resource")
    open_path = options["open"]
    save_path = options["save"]
    resource_path = options["resource"]

    log.detail("Open", open_path)
    log.detail("Save", save_path)
    log.detail("Resource", resource_path)

    incoming = read_file(resource_path)
    if not incoming:
        raise ResError(f"{resource_path!r} contains no resources")

    with PEImage(open_path) as image:
        image.prepare_for_edit()
        results = image.merge(incoming, mode)
        image.save(save_path)
        notes = list(image.notes)

    for entry, outcome in results:
        if outcome == "modified":
            log.modified(entry)
        elif outcome == "added":
            log.added(entry)
    for note in notes:
        log.note(f"  Note: {note}")


def main(argv: Optional[List[str]] = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)

    if not args:
        sys.stderr.write(USAGE)
        return _EXIT_FAILURE

    try:
        options = parse_switches(args)
    except UsageError as exc:
        sys.stderr.write(f"Error: {exc}\n\n{USAGE}")
        return _EXIT_FAILURE

    if "help" in options:
        topic = options.get("help")
        sys.stdout.write(USAGE)
        if topic:
            sys.stdout.write(f"\n(Detailed '{topic}' help is not implemented.)\n")
        return 0

    log = ResourceLog(options.get("log") or DEFAULT_LOG_NAME)
    log.banner([sys.argv[0]] + args)

    try:
        _require(options, "open", "action")
        action = (options["action"] or "").lower()
        if action == "extract":
            _extract(options, log)
        elif action == "addoverwrite":
            _apply_resources(options, log, OVERWRITE)
        elif action == "replace":
            _apply_resources(options, log, REPLACE)
        elif action == "script":
            raise UsageError("use -script FILE; -action script is not a thing")
        else:
            raise UsageError(
                f"action {action!r} is not implemented "
                "(only 'extract' and 'addoverwrite' are)"
            )
    except (UsageError, PEError, ResError, MaskError, OSError) as exc:
        log.failure(str(exc))
        log.flush()
        return _EXIT_FAILURE

    log.success()
    log.flush()
    return 0
