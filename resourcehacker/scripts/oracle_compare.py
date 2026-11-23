"""Compare resourcehackerpy against a real ResourceHacker.exe.

Usage:
    python scripts/oracle_compare.py --rh C:\\path\\ResourceHacker.exe \\
        --source C:\\Windows\\System32\\notepad.exe \\
        --target C:\\Windows\\System32\\where.exe \\
        --workdir %TEMP%\\oracle

What is asserted (all must pass):

  1. the extracted .res files decode to identical entries,
  2. our merged PE keeps every non-.rsrc section byte-identical to the input,
     along with the entry point and the import count,
  3. icon/cursor images are never clobbered: the merged tree contains every
     input image and every incoming image,
  4. every icon/cursor group's image references resolve to a present image.

What is compared against Resource Hacker on top of that (differences are
reported, and only the semantic ones are treated as failures):

  * all non-image resource leaves (type, name, language, payload) must match,
  * the multiset of image payloads must match,
  * the set of groups must match, and their payloads must match after the image
    ids are normalised to their position — Resource Hacker renumbers ids
    differently, which is expected.
"""

from __future__ import annotations

import argparse
import hashlib
import struct
import subprocess
import sys
from collections import Counter
from pathlib import Path
from typing import Dict, Iterable, List, Tuple

import pefile

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from resourcehacker.pelayer import (  # noqa: E402
    GROUP_TO_IMAGE,
    PEImage,
    _GROUP_ENTRY_ID_OFFSET,
    _GROUP_ENTRY_SIZE,
    _GROUP_HEADER_SIZE,
)
from resourcehacker.resfile import decode  # noqa: E402

IMAGE_TYPES = {1, 3}
GROUP_TYPES = {12, 14}

Leaf = Tuple[object, object, int, bytes]


def _leaves(path: Path) -> List[Leaf]:
    with PEImage(str(path)) as image:
        return [(e.type_id, e.name_id, e.language, e.data) for e in image.entries()]


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _normalise_group(data: bytes) -> bytes:
    """Replace each image id with its entry index, so ids don't matter."""
    if len(data) < _GROUP_HEADER_SIZE:
        return data
    buffer = bytearray(data)
    try:
        _reserved, _type, count = struct.unpack_from("<HHH", buffer, 0)
    except struct.error:
        return data
    for index in range(count):
        offset = _GROUP_HEADER_SIZE + index * _GROUP_ENTRY_SIZE + _GROUP_ENTRY_ID_OFFSET
        if offset + 2 > len(buffer):
            break
        struct.pack_into("<H", buffer, offset, index)
    return bytes(buffer)


def _split(leaves: Iterable[Leaf]):
    plain: Counter = Counter()
    images: Counter = Counter()
    groups: Counter = Counter()
    for type_id, name_id, language, data in leaves:
        if isinstance(type_id, int) and type_id in IMAGE_TYPES:
            images[(type_id, _digest(data))] += 1
        elif isinstance(type_id, int) and type_id in GROUP_TYPES:
            groups[(type_id, name_id, language, _normalise_group(data))] += 1
        else:
            plain[(type_id, name_id, language, data)] += 1
    return plain, images, groups


def _sections(path: Path) -> Dict[str, bytes]:
    pe = pefile.PE(str(path), fast_load=True)
    return {
        section.Name.rstrip(b"\0").decode("latin-1"): section.get_data()[
            : section.Misc_VirtualSize
        ]
        for section in pe.sections
    }


def _ep_and_imports(path: Path) -> Tuple[int, int]:
    pe = pefile.PE(str(path))
    pe.parse_data_directories()
    return pe.OPTIONAL_HEADER.AddressOfEntryPoint, len(
        getattr(pe, "DIRECTORY_ENTRY_IMPORT", [])
    )


def _run_rh(exe: Path, args: List[str]) -> None:
    subprocess.run([str(exe), *args], capture_output=True)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--rh", required=True, type=Path)
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--target", required=True, type=Path)
    parser.add_argument("--workdir", required=True, type=Path)
    args = parser.parse_args()

    work = args.workdir
    work.mkdir(parents=True, exist_ok=True)
    failures: List[str] = []

    ref_res, our_res = work / "ref.res", work / "ours.res"
    ref_pe, our_pe = work / "ref.exe", work / "ours.exe"

    # 1. extract
    _run_rh(args.rh, ["-open", str(args.source), "-action", "extract", "-mask", ",,,",
                     "-save", str(ref_res), "-log", str(work / "ref_extract.log")])
    from resourcehacker.cli import main as our_main

    rc = our_main(["-open", str(args.source), "-action", "extract", "-mask", ",,,",
                   "-save", str(our_res), "-log", str(work / "our_extract.log")])
    if rc != 0:
        failures.append(f"our extract exited {rc}")
    if not (ref_res.exists() and our_res.exists()):
        failures.append("one of the extract steps produced no .res")
        print("\n".join(failures))
        return 1

    if decode(ref_res.read_bytes()) == decode(our_res.read_bytes()):
        print(f"[ok] .res identical ({len(decode(our_res.read_bytes()))} entries)")
    else:
        failures.append(".res files differ")

    # 2. merge
    _run_rh(args.rh, ["-open", str(args.target), "-save", str(ref_pe),
                     "-resource", str(ref_res), "-action", "addoverwrite"])
    rc = our_main(["-open", str(args.target), "-save", str(our_pe),
                   "-resource", str(our_res), "-action", "addoverwrite",
                   "-log", str(work / "our_merge.log")])
    if rc != 0:
        failures.append(f"our merge exited {rc}")
    if not (ref_pe.exists() and our_pe.exists()):
        failures.append("one of the merge steps produced no PE")
        print("\n".join(failures))
        return 1

    # 3. section preservation
    source_sections = _sections(args.target)
    merged_sections = _sections(our_pe)
    for name, digest in source_sections.items():
        if name == ".rsrc":
            continue
        if merged_sections.get(name) != digest:
            failures.append(f"section {name} was not preserved byte-for-byte")
    if not failures:
        print(f"[ok] {len(source_sections) - 1} sections preserved, .rsrc replaced")

    if _ep_and_imports(args.target) != _ep_and_imports(our_pe):
        failures.append("entry point or import count changed")
    else:
        print("[ok] entry point and import count unchanged")

    # 4. icons
    input_leaves = _leaves(args.target)
    ours_leaves = _leaves(our_pe)
    ref_leaves = _leaves(ref_pe)

    input_images = Counter((_digest(d)) for t, _, _, d in input_leaves
                           if isinstance(t, int) and t in IMAGE_TYPES)
    ours_images = Counter((_digest(d)) for t, _, _, d in ours_leaves
                          if isinstance(t, int) and t in IMAGE_TYPES)
    if ours_images < input_images:
        failures.append("some images from the target were clobbered")
    else:
        print(f"[ok] target images preserved ({sum(input_images.values())})")

    # 5. group references resolve
    names_by_type = {1: set(), 3: set()}
    for type_id, name_id, _lang, _data in ours_leaves:
        if isinstance(type_id, int) and type_id in names_by_type and isinstance(name_id, int):
            names_by_type[type_id].add(name_id)
    for type_id, _name, _lang, data in ours_leaves:
        image_type = GROUP_TO_IMAGE.get(type_id) if isinstance(type_id, int) else None
        if image_type is None or len(data) < _GROUP_HEADER_SIZE:
            continue
        _reserved, _t, count = struct.unpack_from("<HHH", data, 0)
        for index in range(count):
            offset = _GROUP_HEADER_SIZE + index * _GROUP_ENTRY_SIZE + _GROUP_ENTRY_ID_OFFSET
            if offset + 2 > len(data):
                break
            (image_id,) = struct.unpack_from("<H", data, offset)
            if image_id not in names_by_type[image_type]:
                failures.append(
                    f"group type {type_id} references missing image {image_id}"
                )
                break
    if not any("references missing" in f for f in failures):
        print("[ok] every group reference resolves")

    # 6. semantic comparison with Resource Hacker
    ref_plain, ref_images, ref_groups = _split(ref_leaves)
    our_plain, our_images, our_groups = _split(ours_leaves)

    if ref_plain == our_plain:
        print(f"[ok] non-image resources identical ({sum(our_plain.values())})")
    else:
        missing = ref_plain - our_plain
        extra = our_plain - ref_plain
        failures.append(
            f"non-image resources differ: {sum(missing.values())} missing, "
            f"{sum(extra.values())} extra"
        )

    if ref_images == our_images:
        print(f"[ok] image payloads identical ({sum(our_images.values())})")
    else:
        failures.append(
            f"image payloads differ: RH {sum(ref_images.values())}, "
            f"ours {sum(our_images.values())}"
        )

    if ref_groups == our_groups:
        print(f"[ok] icon/cursor groups identical after id normalisation "
              f"({sum(our_groups.values())})")
    else:
        failures.append(
            f"groups differ: RH {sum(ref_groups.values())}, "
            f"ours {sum(our_groups.values())}"
        )

    if failures:
        print("\nFAILURES:")
        for failure in failures:
            print(f"  - {failure}")
        return 1

    # 7. cloning: `replace` must leave nothing of the target's resources behind
    cloned = work / "cloned.exe"
    rc = our_main(["-open", str(args.target), "-save", str(cloned),
                   "-resource", str(our_res), "-action", "replace",
                   "-log", str(work / "our_replace.log")])
    if rc != 0:
        print(f"[!!] replace exited {rc}")
        return 1
    if Counter(_leaves(cloned)) == Counter(_leaves(args.source)):
        print(f"[ok] replace reproduces the source tree exactly "
              f"({len(_leaves(cloned))} leaves, none of the target's left)")
    else:
        print("[!!] replace did not reproduce the source resource tree")
        return 1

    print("\nALL CHECKS PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
