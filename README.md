# MetaResourceThief.py

Python bundle (built to command-line tools) of `metatwin` (reimplementation of [metatwin](https://github.com/threatexpress/metatwin)), `ResourceHacker` (reimplementations of
[Resource Hacker](https://www.angusj.com/resourcehacker/)), and `SigThief` (included as submodule [SigThief](https://github.com/secretsquirrel/SigThief)).

> /!\ This project is 100% vibe-coded. While I would like to take credit for anything, I honestly can't. It's merely a convenience project that allows the metatwin/ResourceHacker/SigThief stack to run on Linux (without the need for Wine).

- **Familiar command line.** `ResourceHacker -open … -action …` accepts the same
  switches as the original, so an existing script needs only its binary path
  changed.
- **Runs where the originals can't.** Pure Python with one runtime dependency
  (`pe_tools`); both packages install on Linux, and the Docker image needs
  neither Wine nor a Windows host.
- **Leaves the image intact.** After a resource merge every non-`.rsrc` section
  is byte-identical to the input, the entry point and import count are
  unchanged, and the PE checksum is recomputed.
- **One shared library.** The `.res` codec, resource tree and merge logic live
  in `resourcehacker/`; `metatwin` imports them.
- **46 tests** across the two packages, plus an oracle comparison against the
  real Resource Hacker 5.1.8.360.

```console
$ metatwin -s C:\Windows\explorer.exe -t C:\Windows\System32\where.exe -o out --sign
[*] extracted 207 resources from explorer.exe
[*] cloned resources onto where.exe -> 20261123_010935_where_twin.exe
[*] transplanted signature (77680 bytes) -> 20261123_010935_signed_where.exe
[+] output: out\20261123_010935\20261123_010935_signed_where.exe
  FileDescription : Windows Explorer
  CompanyName     : Microsoft Corporation
  FileVersion     : 10.0.26100.9974 (WinBuild.160101.0800)
```

> **The transplanted signature is structurally valid but cryptographically
> invalid.** It still covers the source image's digest, so Windows reports
> `HashMismatch` on the output while displaying the source's signer. That is the
> technique, not a defect in this port — see [SigThief](#sigthief).

---

## Contents

- [Install](#install)
- [The tools](#the-tools)
- [`replace` vs `addoverwrite`](#replace-vs-addoverwrite)
- [Matching Resource Hacker's command line](#matching-resource-hackers-command-line)
- [Verified against Resource Hacker 5.1.8.360](#verified-against-resource-hacker-518360)
- [Deliberate differences](#deliberate-differences)
- [Development](#development)
- [Credits and licences](#credits-and-licences)

## Install

Two local distributions, plus the SigThief submodule:

```console
$ git submodule update --init --recursive
$ pip install -e ./resourcehacker -e ./metatwin
```

`pip` pulls `pe_tools`, the only runtime dependency. Python 3.9+. On Windows
each console script becomes an `.exe` in the environment's `Scripts` directory —
`ResourceHacker.exe` and `metatwin.exe`.

SigThief is not installed: it runs straight from the submodule as
`python sigthief/sigthief.py` (see [below](#sigthief)), and `metatwin --sign`
calls that script. So `--sign` needs the submodule — or `--sigthief PATH` /
`$SIGTHIEF` pointing at a copy — while the resource clone works without it.

### Standalone executables

Single-file executables via PyInstaller, no Python needed on the target:

```console
$ pip install pyinstaller
$ python scripts/build_exes.py
[+] built: ResourceHacker.exe, SigThief.exe, metatwin.exe
```

The three land in `dist/` (with `.exe` on Windows); `SigThief.exe` is built from
the submodule's script. `metatwin.exe` lives outside the checkout, so its
`--sign` needs `--sigthief path\to\sigthief.py`. The build also copies
`THIRD_PARTY_NOTICES.md` and SigThief's `LICENSE` into `dist/`.

### Docker

The image installs both packages and exposes upstream SigThief as `SigThief`;
`ResourceHacker` is the default entry point, so the container takes Resource
Hacker's switches directly. Third-party licence texts are in the image under
`/app/NOTICES`.

```console
$ docker build -t resourcehacker .
$ docker run --rm -v "${PWD}:/work" -w /work resourcehacker \
    -open where.exe -action extract -mask ',,,' -save out.res -log out.log
```

Switch tools with `--entrypoint`:

```console
$ docker run --rm -v "${PWD}:/work" -w /work --entrypoint SigThief resourcehacker \
    -i source.exe -t target.exe -o signed.exe
```

## The tools

```
resourcehacker/    ResourceHacker CLI + the shared PE library
├── resourcehacker/    .res codec, resource tree, merge logic
├── tests/
└── scripts/oracle_compare.py
metatwin/          metatwin CLI (imports resourcehacker)
sigthief/          upstream SigThief, pinned as a git submodule
```

### ResourceHacker

```console
$ ResourceHacker -open source.exe -action extract -mask ',,,' -save out.res -log out.log
$ ResourceHacker -open target.exe -save new.exe -resource out.res -action replace
```

| Action | What it does |
|---|---|
| `extract` | write the resources matched by `-mask` to a `.res` file |
| `addoverwrite` | merge `-resource` into the opened image, overwriting collisions |
| `replace` | discard the image's resource tree and install `-resource` verbatim — the cloning action |

Switches may be abbreviated when unambiguous (`-op`, `-sa`, `-act`). `-save`
names the output file. Exit status is `0` on success and `-1` (`0xFFFFFFFF`,
Resource Hacker's own failure code) otherwise.

### SigThief

The original tool, vendored rather than ported: `sigthief/` is a git submodule
pinned to [secretsquirrel/SigThief](https://github.com/secretsquirrel/SigThief).
The script is dependency-free Python, so it runs on Linux and Windows as-is:

```console
$ python sigthief/sigthief.py -i source.exe -t target.exe -o signed.exe
Output file: signed.exe
Signature appended.
FIN.
```

All of the original's modes are available — `-r` rip to disk, `-s`/`-a` add from
a signature file, `-c` check, `-T` truncate. The Docker image and
`dist/SigThief.exe` invoke this same script under the original's name, and
`metatwin --sign` loads it to do the certificate copy.

The appended bytes are a valid certificate table and Windows parses them, but
the `SignedData` covers the source image's digest, so verification fails on
anything whose image differs from the source.

### metatwin

```console
$ metatwin -s source.exe -t payload.exe -o outdir --sign
```

The whole pipeline in one command, mirroring `Invoke-MetaTwin`:

1. extract every resource of the source into a `.res`,
2. install it into the target with `replace` semantics — nothing of the target's
   own resources survives,
3. optionally copy the source's certificate table with SigThief (`--sign`;
   it finds `sigthief/sigthief.py`, or takes `--sigthief`/`$SIGTHIEF`),
4. timestomp the output to the source's access and modification times
   (creation time too, on Windows),
5. print the resulting version info.

Each run creates `outdir/<YYYYMMDD_HHMMSS>/` holding the `.res`, the unsigned
`*_twin.exe` and, with `--sign`, the `*_signed_*` output.

## `replace` vs `addoverwrite`

`addoverwrite` merges, matching Resource Hacker: resources the target has and
the `.res` does not are kept, and incoming icons are renumbered so they don't
collide. `replace` discards the target's resource tree entirely — the cloning
action.

Measured with a 243-resource `.res` onto `where.exe`: Resource Hacker's
`addoverwrite` output contains 85 resource leaves that are not in the source;
`replace` leaves 0 and reproduces the source tree exactly.

## Matching Resource Hacker's command line

Two details trip up scripts ported from the original, and both are reproduced
rather than fixed:

- **`-mask`** takes `Type,Name,Language` with two commas required. An empty
  field or `*` means "any". The language field falls back to "any" whenever it
  isn't an integer, which is why `-mask ,,,` selects everything — the third
  comma lands in the language field, which then can't parse as a number.
  `ICON` and `CURSOR` imply the group *and* its images, as in the original.
  A one-comma mask such as `ICON,MAINICON` is rejected, as it is there.
- **`-log`** writes UTF-16LE *without* a BOM, CRLF line endings, ending in
  `Success!` or `Error: …` + `Failed!` — the shape
  `Select-String -Encoding Unicode -Pattern "Failed"` expects. `-log CONSOLE`
  prints the log instead, `-log NUL` discards it; the default is
  `resourcehacker.log`.

> In PowerShell, comma-separated arguments are parsed as arrays: quote the mask
> as `-mask ',,,'`.

## Verified against Resource Hacker 5.1.8.360

`resourcehacker/scripts/oracle_compare.py` drives a real `ResourceHacker.exe`
and this implementation over the same inputs and compares the results. On
`notepad.exe`, `where.exe`, `powershell.exe`, `explorer.exe` (embedded
signature) and 32-bit `SysWOW64\where.exe` the recorded run showed:

- extracted `.res` files decode to identical entries (243/243);
- every non-`.rsrc` section of the merged PE stays byte-identical, as do the
  entry point and import count;
- no target image is clobbered and every icon/cursor group reference resolves;
- 157 non-image resources, 56–237 image payloads and 31–54 groups match
  Resource Hacker's output;
- `replace` reproduces the source tree exactly.

Running `metatwin --sign` on `explorer.exe` → `where.exe` gives an output whose
version info reads back as the source's (`FileDescription: Windows Explorer`),
whose timestamps match the source's, and whose signature shows the source's
signer with status `HashMismatch`.

To rerun the comparison you need a real `ResourceHacker.exe` and `pefile`:

```console
$ pip install -e ./resourcehacker[dev]
$ python resourcehacker/scripts/oracle_compare.py \
    --rh C:\tools\ResourceHacker.exe \
    --source C:\Windows\System32\notepad.exe \
    --target C:\Windows\System32\where.exe \
    --workdir out\oracle
```

It prints one `[ok]` line per successful check and exits non-zero if any
semantic check fails.

## Deliberate differences

- **No `.rc` compiler or decompiler.** No image extraction, no GUI, no
  `add`/`addskip`/`modify`/`delete`/`changelanguage`, no `-script`.
- **Signatures are stripped by the resource step**, because `pe_tools` cannot
  relocate the certificate table. `SigThief` — or `metatwin --sign` — adds one
  back.
- **The section table is preserved.** On some inputs Resource Hacker rebuilds
  the image into a different layout (dropping `fothk`/`.rdata`/`.pdata`); this
  implementation keeps every non-`.rsrc` section byte-for-byte.
- **`addoverwrite` renumbers icon and cursor images** and re-creates the groups
  at language 0, as Resource Hacker does, but the allocation order differs, so
  outputs are not byte-identical.
- **The checksum is always recomputed.**
- **`extract` always writes a `.res`**, even for a single match. No matches
  writes no file and still logs `Success!`, matching the original.

## Development

```console
$ pip install -e ./resourcehacker[dev] -e ./metatwin[dev]
$ cd resourcehacker && python -m pytest    # 42 passed
$ cd ../metatwin    && python -m pytest    #  4 passed
```

Run each suite from inside its own directory so imports resolve to the package
and not the folder. Tests that need real Windows binaries skip themselves
elsewhere.

The `Makefile` wraps these: `make submodules`, `make install`, `make test`,
`make build` (PyInstaller executables) and `make docker`, for systems that have
`make`.

## Credits and licences

This project is MIT-licensed (see [LICENSE](LICENSE)). Third-party licence
texts, and precisely what triggers each, are in
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).

- [Resource Hacker](https://www.angusj.com/resourcehacker/) by Angus Johnson —
  behavioural reference only. Resource Hacker is proprietary freeware: its CLI
  switches, `-mask` grammar and log format are reproduced for compatibility,
  but no code is copied or distributed here. 5.1.8.360 is the version followed.
- [metatwin](https://github.com/threatexpress/metatwin) by Threat Express
  ([Joe Vest](https://twitter.com/joevest)) — `metatwin/` is a port of
  `metatwin.ps1` and therefore a derivative work under the original's MIT
  licence, Copyright (c) 2024 Threat Express. The notice ships in this
  repository, in the `metatwin` package (`NOTICE`), in the Docker image and
  next to the executables in `dist/`.
- [SigThief](https://github.com/secretsquirrel/SigThief) by Josh Pitts
  ([@midnite_runr](https://twitter.com/midnite_runr)) — vendored as a git
  submodule and redistributed as source, in the Docker image and as
  `dist/SigThief.exe` under BSD-3-Clause, Copyright (c) 2017 Josh Pitts. See
  [sigthief/LICENSE](sigthief/LICENSE).
- [pe_tools](https://github.com/avast/pe_tools) by Avast — runtime dependency,
  not vendored; used for PE parsing and resource serialisation.
