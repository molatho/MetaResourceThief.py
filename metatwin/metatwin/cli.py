"""A Python equivalent of metatwin.ps1: clone a source binary's metadata onto a target.

    metatwin -s source.exe -t target.exe -o outdir [--sign]

Steps, mirroring the original script:

1. extract every resource of the source into a ``.res``,
2. install that ``.res`` into the target with *replace* semantics, so none of
   the target's own resources survive,
3. optionally copy the source's Authenticode certificate table with SigThief —
   the upstream script from the ``sigthief`` submodule, not a port of it,
4. timestomp the output to the source's timestamps,
5. print the resulting version info.

Unlike the original this runs on Linux as well as Windows, and needs neither
PowerShell nor a compiled ``sigthief.exe``.
"""

from __future__ import annotations

import argparse
import contextlib
import datetime as _dt
import io
import os
import sys
import types
from pathlib import Path
from typing import Optional

from resourcehacker.pelayer import PEImage, REPLACE
from resourcehacker.resfile import write_file

RT_VERSION = 16


class SignatureCopyError(RuntimeError):
    """Raised when SigThief cannot supply a signature."""


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


def _sigthief_script(explicit: Optional[Path]) -> Optional[Path]:
    """Locate SigThief's script: explicit path, ``$SIGTHIEF``, then the repo."""
    if explicit is not None:
        candidate = Path(explicit)
        return candidate.resolve() if candidate.is_file() else None
    override = os.environ.get("SIGTHIEF")
    if override:
        candidate = Path(override)
        return candidate.resolve() if candidate.is_file() else None

    candidates = []
    if getattr(sys, "frozen", False):
        # A PyInstaller build sits outside the checkout; allow a sibling copy.
        candidates.append(
            Path(sys.executable).resolve().parent / "sigthief" / "sigthief.py"
        )
    candidates.append(Path(__file__).resolve().parents[2] / "sigthief" / "sigthief.py")
    candidates.append(Path.cwd() / "sigthief" / "sigthief.py")
    return next((path for path in candidates if path.is_file()), None)


def _load_sigthief(script: Path):
    """Load upstream ``sigthief.py`` as a module without running its CLI.

    Compiled straight from source rather than imported through the loader, so
    no ``__pycache__`` is written into the submodule.
    """
    module = types.ModuleType("_sigthief_upstream")
    module.__file__ = str(script)
    exec(compile(script.read_text(encoding="utf-8"), str(script), "exec"), module.__dict__)
    return module


def _copy_signature(script: Path, source: Path, target: Path, output: Path) -> int:
    """Copy ``source``'s certificate table onto ``target`` using SigThief.

    Returns the size of the transplanted blob.  SigThief's output is captured:
    metatwin reports the result itself.
    """
    module = _load_sigthief(script)
    transcript = io.StringIO()
    try:
        with contextlib.redirect_stdout(transcript):
            certificate = module.copyCert(str(source))
    except SystemExit:
        reason = (
            "source has no embedded signature"
            if "Not signed" in transcript.getvalue()
            else "sigthief refused the source"
        )
        raise SignatureCopyError(reason) from None
    with contextlib.redirect_stdout(transcript):
        module.writeCert(certificate, str(target), str(output))
    return len(certificate)


def run(
    source: Path,
    target: Path,
    out_dir: Path,
    do_sign: bool,
    sigthief_script: Optional[Path] = None,
) -> int:
    stamp = _timestamp_slug(_dt.datetime.now())
    work = out_dir / stamp
    work.mkdir(parents=True, exist_ok=True)

    resource_file = work / f"{stamp}_{source.name}.res"
    twin = work / f"{stamp}_{target.stem}_twin{target.suffix}"
    signed = work / f"{stamp}_signed_{target.stem}{target.suffix}"

    # 1. extract the source's resources
    with PEImage(str(source)) as image:
        entries = image.entries()
    if not entries:
        raise SystemExit(f"error: {source} has no resources to copy")
    write_file(str(resource_file), entries)
    print(f"[*] extracted {len(entries)} resources from {source.name}")

    # 2. install them into the target, replacing everything
    with PEImage(str(target)) as image:
        image.prepare_for_edit()
        image.merge(entries, REPLACE)
        image.save(str(twin))
    print(f"[*] cloned resources onto {target.name} -> {twin.name}")

    # 3. signature, by upstream SigThief
    final = twin
    if do_sign:
        script = sigthief_script or _sigthief_script(None)
        if script is None:
            raise SignatureCopyError(
                "sigthief.py not found; pass --sigthief PATH, set SIGTHIEF, "
                "or run `git submodule update --init`"
            )
        try:
            size = _copy_signature(script, source, twin, signed)
            final = signed
            print(f"[*] transplanted signature ({size} bytes) -> {signed.name}")
        except SignatureCopyError as exc:
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
    parser.add_argument(
        "--sigthief",
        type=Path,
        metavar="SCRIPT",
        help="sigthief.py to use for --sign (default: the submodule, or $SIGTHIEF)",
    )
    args = parser.parse_args(argv)

    for path in (args.source, args.target):
        if not path.exists():
            print(f"error: {path} does not exist", file=sys.stderr)
            return 1

    script = None
    if args.sign:
        script = _sigthief_script(args.sigthief)
        if script is None:
            print(
                "error: --sign needs SigThief; pass --sigthief PATH, set SIGTHIEF, "
                "or run `git submodule update --init`",
                file=sys.stderr,
            )
            return 1

    args.out_dir.mkdir(parents=True, exist_ok=True)
    try:
        return run(args.source, args.target, args.out_dir, args.sign, script)
    except SignatureCopyError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
