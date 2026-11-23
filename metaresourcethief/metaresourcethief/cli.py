"""MetaResourceThief: copy a PE's resources and/or its signature in one step.

    MetaResourceThief -s source.exe -t target.exe -o out.exe [--sign] [--no-metadata]

- Resources are installed with ``replace`` semantics by ResourceHacker's
  library (``resourcehacker.pelayer.copy_resources``), the same merge
  ``metatwin`` performs.
- The signature is copied by upstream SigThief, through
  ``metatwin.signature.copy_signature``.

Both halves are optional and independent::

    -s src -t tgt -o out --sign                resources + signature
    -s src -t tgt -o out                       resources only
    -s src -t tgt -o out --sign --no-metadata  signature only
"""

from __future__ import annotations

import argparse
import os
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Optional

from metatwin.signature import SignatureError, copy_signature
from resourcehacker.pelayer import PEError, copy_resources


def _scratch(output: Path) -> Path:
    """Create an empty scratch file next to ``output``."""
    handle, name = tempfile.mkstemp(
        dir=str(output.parent), prefix=f"{output.name}.", suffix=".tmp"
    )
    os.close(handle)
    return Path(name)


def run(
    source: Path,
    target: Path,
    output: Path,
    copy_metadata: bool,
    do_sign: bool,
) -> int:
    staged = _scratch(output)
    signed = None
    try:
        if copy_metadata:
            count = copy_resources(str(source), str(target), str(staged))
            print(f"[*] copied {count} resources from {source.name} -> {output.name}")
        else:
            shutil.copyfile(target, staged)
            print(f"[*] metadata skipped; copied {target.name} -> {output.name}")

        if do_sign:
            signed = _scratch(output)
            size = copy_signature(source, staged, signed)
            os.replace(signed, staged)
            signed = None
            print(
                f"[*] copied signature ({size} bytes) "
                f"from {source.name} -> {output.name}"
            )

        os.replace(staged, output)
        staged = None
    finally:
        for leftover in (staged, signed):
            if leftover is not None and leftover.exists():
                leftover.unlink()

    print(f"[+] output: {output}")
    return 0


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="MetaResourceThief",
        description="Copy a PE's resources and/or its Authenticode signature.",
        epilog=(
            "Copy resources with -s/-t/-o; add --sign for the signature too; "
            "add --no-metadata to copy the signature only."
        ),
    )
    parser.add_argument(
        "-s", "--source", required=True, type=Path,
        help="binary to copy the metadata from",
    )
    parser.add_argument(
        "-t", "--target", required=True, type=Path,
        help="binary to copy the metadata to",
    )
    parser.add_argument(
        "-o", "--output", required=True, type=Path,
        help="path of the file to write",
    )
    parser.add_argument(
        "--sign",
        action="store_true",
        help="also copy the source's Authenticode certificate table with SigThief",
    )
    parser.add_argument(
        "--no-metadata",
        action="store_true",
        help="skip the resource copy (use with --sign for signature only)",
    )
    args = parser.parse_args(argv)

    for path in (args.source, args.target):
        if not path.exists():
            print(f"error: {path} does not exist", file=sys.stderr)
            return 1
    if not args.sign and args.no_metadata:
        print(
            "error: nothing to copy: --no-metadata was given without --sign",
            file=sys.stderr,
        )
        return 1
    if args.output.resolve() in (args.source.resolve(), args.target.resolve()):
        print(
            "error: --output must differ from --source and --target",
            file=sys.stderr,
        )
        return 1

    args.output.parent.mkdir(parents=True, exist_ok=True)
    try:
        return run(
            args.source,
            args.target,
            args.output,
            copy_metadata=not args.no_metadata,
            do_sign=args.sign,
        )
    except (OSError, ValueError, PEError, SignatureError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
