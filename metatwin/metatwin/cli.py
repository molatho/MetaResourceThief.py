"""A Python equivalent of metatwin.ps1: clone a source binary's metadata onto a target.

    metatwin -s source.exe -t target.exe -o outdir [--sign]

Steps, mirroring the original script:

1. extract every resource of the source into a ``.res``,
2. install that ``.res`` into the target with *replace* semantics, so none of
   the target's own resources survive,
3. optionally copy the source's Authenticode certificate table with SigThief,
   imported from the ``sigthief`` distribution built from ``packaging/``,
4. timestomp the output to the source's timestamps,
5. print the resulting version info.

Unlike the original this runs on Linux as well as Windows, and needs neither
PowerShell nor a compiled ``sigthief.exe``.
"""

from __future__ import annotations

import argparse
import datetime as _dt
import os
import sys
from pathlib import Path
from typing import Optional

from resourcehacker.pelayer import PEError, PEImage, copy_resources

from .signature import SignatureError, copy_signature

RT_VERSION = 16


def _timestamp_slug(now: _dt.datetime) -> str:
    return now.strftime("%Y%m%d_%H%M%S")


def _print_version_info(path: Path) -> None:
    try:
        from pe_tools.version_info import parse_version_info
    except Exception:  # pragma: no cover - pe_tools always ships it
        return

    with PEImage(str(path)) as image:
        version_entries = [
            entry for entry in image.entries() if entry.type_id == RT_VERSION
        ]
    if not version_entries:
        print("  version info: (none)")
        return

    for entry in version_entries:
        try:
            info = parse_version_info(entry.data)
            strings = info.string_file_info()
            fixed = info.get_fixed_info()
        except Exception as exc:
            print(f"  version info: unreadable ({exc})")
            continue
        for _lang, table in strings.items():
            for key in ("ProductName", "FileDescription", "CompanyName", "FileVersion"):
                if key in table:
                    print(f"  {key:16}: {table[key]}")
        print(f"  fixed FileVersion: {fixed.file_version}")


def _set_creation_time(path: Path, nanoseconds: int) -> None:
    """Best-effort: copy the creation time too. Windows only."""
    if os.name != "nt":
        return
    try:
        import ctypes
        from ctypes import wintypes

        FILE_WRITE_ATTRIBUTES = 0x0100
        OPEN_EXISTING = 3
        handle = ctypes.windll.kernel32.CreateFileW(
            str(path),
            FILE_WRITE_ATTRIBUTES,
            0,
            None,
            OPEN_EXISTING,
            0x02000000,  # FILE_FLAG_BACKUP_SEMANTICS
            None,
        )
        if handle == -1:
            return
        try:
            ticks = nanoseconds // 100 + 116444736000000000  # epoch -> 1601
            filetime = wintypes.FILETIME(ticks & 0xFFFFFFFF, ticks >> 32)
            ctypes.windll.kernel32.SetFileTime(
                handle, ctypes.byref(filetime), None, None
            )
        finally:
            ctypes.windll.kernel32.CloseHandle(handle)
    except Exception:
        pass


def _timestomp(source: Path, output: Path) -> None:
    stat = source.stat()
    os.utime(output, ns=(stat.st_atime_ns, stat.st_mtime_ns))
    _set_creation_time(output, stat.st_ctime_ns)


def run(source: Path, target: Path, out_dir: Path, do_sign: bool) -> int:
    stamp = _timestamp_slug(_dt.datetime.now())
    work = out_dir / stamp
    work.mkdir(parents=True, exist_ok=True)

    resource_file = work / f"{stamp}_{source.name}.res"
    twin = work / f"{stamp}_{target.stem}_twin{target.suffix}"
    signed = work / f"{stamp}_signed_{target.stem}{target.suffix}"

    # 1+2. extract the source's resources and install them into the target
    count = copy_resources(
        str(source), str(target), str(twin), resfile=str(resource_file)
    )
    print(f"[*] extracted {count} resources from {source.name}")
    print(f"[*] cloned resources onto {target.name} -> {twin.name}")

    # 3. signature
    final = twin
    if do_sign:
        try:
            size = copy_signature(source, twin, signed)
            final = signed
            print(f"[*] transplanted signature ({size} bytes) -> {signed.name}")
        except SignatureError as exc:
            print(f"[!] no signature copied: {exc}")

    # 4. timestomp
    _timestomp(source, final)

    # 5. report
    print(f"[+] output: {final}")
    _print_version_info(final)
    return 0


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="metatwin",
        description="Clone a source PE's resources and signature onto a target.",
    )
    parser.add_argument("-s", "--source", required=True, type=Path)
    parser.add_argument("-t", "--target", required=True, type=Path)
    parser.add_argument("-o", "--out-dir", required=True, type=Path)
    parser.add_argument(
        "--sign",
        action="store_true",
        help="copy the source's Authenticode certificate table with SigThief",
    )
    args = parser.parse_args(argv)

    for path in (args.source, args.target):
        if not path.exists():
            print(f"error: {path} does not exist", file=sys.stderr)
            return 1

    args.out_dir.mkdir(parents=True, exist_ok=True)
    try:
        return run(args.source, args.target, args.out_dir, args.sign)
    except (OSError, ValueError, PEError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
