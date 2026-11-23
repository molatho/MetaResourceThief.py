#!/usr/bin/env python3
"""Build standalone single-file executables for the tools.

    python scripts/build_exes.py

Outputs landing in ``dist/``: ``ResourceHacker``, ``metatwin`` and
``MetaResourceThief`` (with ``.exe`` on Windows), plus ``SigThief``, built from
the upstream script in the ``packaging/sigthief`` submodule. The third-party
notices are copied alongside them. Requires ``pip install pyinstaller`` and an
initialised submodule (``git submodule update --init``).
"""

from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

#: Tools implemented by packages in this repository: (name, module, hidden imports).
TOOLS = [
    ("ResourceHacker", "resourcehacker.cli", ()),
    ("metatwin", "metatwin.cli", ()),
    ("MetaResourceThief", "metaresourcethief.cli", ()),
]

#: Upstream tools vendored as git submodules: (name, script path).
SUBMODULE_TOOLS = [
    ("SigThief", ROOT / "packaging" / "sigthief" / "sigthief.py"),
]


def _pyinstaller(
    name: str,
    entry: Path,
    search_paths: list[Path],
    dist: Path,
    build: Path,
    hidden_imports: tuple[str, ...] = (),
) -> int:
    command = [
        sys.executable,
        "-m",
        "PyInstaller",
        "--onefile",
        "--noconfirm",
        "--clean",
        "--name",
        name,
        "--distpath",
        str(dist),
        "--workpath",
        str(build),
        "--specpath",
        str(build),
    ]
    for module in hidden_imports:
        command.extend(["--hidden-import", module])
    for path in search_paths:
        command.extend(["--paths", str(path)])
    command.append(str(entry))
    print(f"[*] building {name}")
    return subprocess.run(command).returncode


def main() -> int:
    try:
        import PyInstaller  # noqa: F401
    except ImportError:
        print("error: PyInstaller is not installed (pip install pyinstaller)", file=sys.stderr)
        return 1

    for name, script in SUBMODULE_TOOLS:
        if not script.is_file():
            print(
                f"error: {script.relative_to(ROOT)} is missing; "
                "run `git submodule update --init` first",
                file=sys.stderr,
            )
            return 1

    dist = ROOT / "dist"
    build = ROOT / "build"
    dist.mkdir(exist_ok=True)
    build.mkdir(exist_ok=True)

    # PyInstaller cannot follow setuptools' editable-install finders, so point
    # it at the source trees explicitly.
    search_paths = [
        ROOT / name for name in ("resourcehacker", "metatwin", "metaresourcethief")
    ]

    with tempfile.TemporaryDirectory() as tmp:
        for name, module, hidden_imports in TOOLS:
            launcher = Path(tmp) / f"{name.lower()}_launcher.py"
            launcher.write_text(
                "import sys\n"
                f"from {module} import main\n"
                "sys.exit(main())\n",
                encoding="utf-8",
            )
            result = _pyinstaller(
                name, launcher, search_paths, dist, build, hidden_imports
            )
            if result != 0:
                print(f"error: PyInstaller failed for {name}", file=sys.stderr)
                return result

        for name, script in SUBMODULE_TOOLS:
            result = _pyinstaller(name, script, search_paths, dist, build)
            if result != 0:
                print(f"error: PyInstaller failed for {name}", file=sys.stderr)
                return result

    for notice, target in (
        (ROOT / "THIRD_PARTY_NOTICES.md", "THIRD_PARTY_NOTICES.md"),
        (ROOT / "packaging" / "sigthief" / "LICENSE", "SigThief-LICENSE"),
    ):
        if notice.is_file():
            shutil.copy2(notice, dist / target)

    expected = {name for name, *_ in TOOLS} | {name for name, _ in SUBMODULE_TOOLS}
    built = sorted(
        path.name
        for path in dist.iterdir()
        if path.is_file() and path.stem in expected
    )
    print(f"[+] built: {', '.join(built)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
