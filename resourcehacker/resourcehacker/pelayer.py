"""PE resource-tree access, backed by ``pe_tools``.

``pe_tools`` already does the hard part correctly: it re-serialises the resource
directory, grows ``.rsrc``, moves the sections that follow it and patches the
data directories.  This module is therefore a thin, opinionated wrapper that

* turns the tree into :class:`~resourcehacker.resfile.ResourceEntry` objects,
* applies merge semantics (add / add-overwrite / add-skip / modify),
* deals with the certificate table the same way ``peresed`` does, and
* writes the result with a recomputed PE checksum.
"""

from __future__ import annotations

from dataclasses import replace
import os
import struct
from typing import Dict, Iterable, List, Optional, Tuple

import grope
from pe_tools import parse_pe
from pe_tools.pe_parser import IMAGE_DIRECTORY_ENTRY_RESOURCE
from pe_tools.rsrc import pe_resources_prepack

from .resfile import ResourceEntry, write_file

#: How a merge treats an entry that already exists in the target.
OVERWRITE = "addoverwrite"
SKIP = "addskip"
MODIFY_ONLY = "modify"
ADD_STRICT = "add"
#: Discard the target's resource tree and install the incoming one verbatim.
#: This is what cloning wants: nothing of the target's resources survives, and
#: the result matches the source's `.rsrc` entry for entry.
REPLACE = "replace"

#: Icon and cursor *images* are addressed by number from their group resource.
#: Adding them under their original ids would overwrite same-numbered images in
#: the target — and silently re-point the target's own groups at our images.  So
#: images get fresh ids and the groups that reference them are patched.
IMAGE_TYPE_TO_GROUP = {3: 14, 1: 12}  # RT_ICON -> RT_GROUP_ICON, RT_CURSOR -> RT_GROUP_CURSOR
GROUP_TO_IMAGE = {group: image for image, group in IMAGE_TYPE_TO_GROUP.items()}

#: Size of one GRPICONDIRENTRY; the nID field sits 12 bytes into it.
_GROUP_ENTRY_SIZE = 14
_GROUP_ENTRY_ID_OFFSET = 12
_GROUP_HEADER_SIZE = 6


def _patch_group_payload(data: bytes, image_type: int, mapping: Dict[Tuple[int, int], int]) -> bytes:
    """Rewrite the image ids inside a GRPICONDIR payload."""
    if len(data) < _GROUP_HEADER_SIZE:
        return data
    try:
        _reserved, _type, count = struct.unpack_from("<HHH", data, 0)
    except struct.error:
        return data
    buffer = bytearray(data)
    for index in range(count):
        offset = _GROUP_HEADER_SIZE + index * _GROUP_ENTRY_SIZE + _GROUP_ENTRY_ID_OFFSET
        if offset + 2 > len(buffer):
            break
        (old_id,) = struct.unpack_from("<H", buffer, offset)
        new_id = mapping.get((image_type, old_id))
        if new_id is not None:
            struct.pack_into("<H", buffer, offset, new_id)
    return bytes(buffer)


def _next_free_id(tree: Dict[object, object], image_type: int) -> int:
    existing = [name for name in tree.get(image_type, {}) if isinstance(name, int)]
    return (max(existing) + 1) if existing else 1


class PEError(RuntimeError):
    """Raised when a PE file cannot be read or rewritten."""


class PEImage:
    """A PE file opened for resource extraction and/or editing."""

    def __init__(self, path: str) -> None:
        self.path = path
        self.notes: List[str] = []
        self._handle = open(path, "rb")
        try:
            self._pe = parse_pe(grope.wrap_io(self._handle))
        except Exception as exc:  # pe_tools raises a variety of errors
            self._handle.close()
            raise PEError(f"cannot parse {path!r} as a PE file: {exc}") from exc

    # -- lifecycle ---------------------------------------------------------

    def close(self) -> None:
        self._handle.close()

    def __enter__(self) -> "PEImage":
        return self

    def __exit__(self, *_exc) -> None:
        self.close()

    # -- reading -----------------------------------------------------------

    def resources(self) -> Dict[object, Dict[object, Dict[int, bytes]]]:
        try:
            tree = self._pe.parse_resources()
        except Exception as exc:
            raise PEError(f"cannot read the resource tree of {self.path!r}: {exc}") from exc
        return tree or {}

    def entries(self) -> List[ResourceEntry]:
        """Flatten the resource tree into entries, in tree order."""
        result: List[ResourceEntry] = []
        for type_id, names in self.resources().items():
            for name_id, languages in names.items():
                for language, data in languages.items():
                    result.append(
                        ResourceEntry(
                            type_id=type_id,
                            name_id=name_id,
                            language=int(language),
                            data=bytes(data),
                        )
                    )
        return result

    # -- editing -----------------------------------------------------------

    def prepare_for_edit(self) -> None:
        """Reject files we cannot rewrite, and normalise signatures/trailers.

        ``pe_tools`` can only *remove* an embedded signature; it cannot relocate
        the certificate table the way Resource Hacker does.  Stripping is
        deliberate: metatwin re-signs the output with SigThief afterwards, and a
        stale certificate would only confuse that step.
        """
        if self._pe.has_signature():
            self._pe.remove_signature()
            self.notes.append("signature removed (pe_tools cannot relocate it)")
        elif self._pe.has_trailer():
            # Overlay data (installers, appended payloads) is preserved as-is.
            self.notes.append("trailing data preserved")

        if not self._pe.is_dir_safely_resizable(IMAGE_DIRECTORY_ENTRY_RESOURCE):
            raise PEError(
                f"the resource section of {self.path!r} is not safely resizable"
            )

    def _renumber_images(
        self,
        tree: Dict[object, object],
        entries: List[ResourceEntry],
    ) -> List[ResourceEntry]:
        """Give incoming icon/cursor images fresh ids and patch their groups.

        Icon and cursor images are referenced by number from their group
        resource, so importing them under their original ids would overwrite
        same-numbered images already in the target and silently re-point the
        target's groups at our payloads.  Resource Hacker renumbers them; so do
        we.  The ids we hand out are sequential from the current maximum, which
        is deterministic but not guaranteed to match Resource Hacker's order.
        """
        if not any(entry.type_id in IMAGE_TYPE_TO_GROUP for entry in entries):
            return entries

        counters = {
            image_type: _next_free_id(tree, image_type)
            for image_type in IMAGE_TYPE_TO_GROUP
        }
        mapping: Dict[Tuple[int, int], int] = {}
        rewritten: List[ResourceEntry] = []

        for entry in entries:
            if entry.type_id in IMAGE_TYPE_TO_GROUP and isinstance(entry.name_id, int):
                new_id = counters[entry.type_id]
                counters[entry.type_id] += 1
                mapping.setdefault((entry.type_id, entry.name_id), new_id)
                # Resource Hacker re-creates images at language 0 rather than
                # keeping the language they had in the .res.
                rewritten.append(replace(entry, name_id=new_id, language=0))
            else:
                rewritten.append(entry)

        patched: List[ResourceEntry] = []
        for entry in rewritten:
            image_type = GROUP_TO_IMAGE.get(entry.type_id)
            if image_type is not None:
                entry = replace(
                    entry,
                    data=_patch_group_payload(entry.data, image_type, mapping),
                    language=0,
                )
            patched.append(entry)
        return patched

    def merge(
        self,
        incoming: Iterable[ResourceEntry],
        mode: str = OVERWRITE,
    ) -> List[Tuple[ResourceEntry, str]]:
        """Merge entries into the tree; returns ``(entry, outcome)`` pairs.

        ``outcome`` is ``"added"``, ``"modified"`` or ``"skipped"``, which is
        what the log reports.

        ``REPLACE`` starts from an empty tree instead of the target's, and does
        not renumber images: the incoming entries are installed exactly as they
        appear in the ``.res``, so the result matches the source's resource tree.
        """
        if mode == REPLACE:
            tree: Dict[object, object] = {}
            incoming = list(incoming)
        else:
            tree = self.resources()
            incoming = list(incoming)
            if mode == OVERWRITE:
                incoming = self._renumber_images(tree, incoming)

        results: List[Tuple[ResourceEntry, str]] = []

        for entry in incoming:
            names = tree.setdefault(entry.type_id, {})
            slots = names.setdefault(entry.name_id, {})
            exists = entry.language in slots

            if mode in (OVERWRITE, REPLACE):
                slots[entry.language] = entry.data
                results.append((entry, "modified" if exists else "added"))
            elif mode == SKIP:
                if exists:
                    results.append((entry, "skipped"))
                else:
                    slots[entry.language] = entry.data
                    results.append((entry, "added"))
            elif mode == MODIFY_ONLY:
                if exists:
                    slots[entry.language] = entry.data
                    results.append((entry, "modified"))
                else:
                    results.append((entry, "skipped"))
            elif mode == ADD_STRICT:
                if exists:
                    raise PEError(f"resource already exists: {entry.label()}")
                slots[entry.language] = entry.data
                results.append((entry, "added"))
            else:
                raise ValueError(f"unknown merge mode {mode!r}")

        self._tree = tree
        return results

    def save(self, out_path: str, update_checksum: bool = True) -> None:
        """Write the (possibly edited) image to ``out_path``."""
        if os.path.exists(out_path) and os.path.samefile(self.path, out_path):
            raise PEError("refusing to overwrite the input file; -save must name a new file")

        tree = getattr(self, "_tree", None)
        if tree is None:
            tree = self.resources()

        prepacked = pe_resources_prepack(tree)
        address = self._pe.resize_directory(
            IMAGE_DIRECTORY_ENTRY_RESOURCE, prepacked.size
        )
        self._pe.set_directory(IMAGE_DIRECTORY_ENTRY_RESOURCE, prepacked.pack(address))

        # ``peresed`` only honours --update-checksum on its in-place path; call
        # to_blob directly so the checksum is always recomputed.
        blob = self._pe.to_blob(update_checksum=update_checksum)
        with open(out_path, "wb") as handle:
            grope.dump(blob, handle)


def read_entries(path: str) -> List[ResourceEntry]:
    """Read the resource tree of a PE file without keeping it open."""
    with PEImage(path) as image:
        return image.entries()


def copy_resources(
    source: str, target: str, output: str, resfile: Optional[str] = None
) -> int:
    """Install every resource of ``source`` into ``target``, writing ``output``.

    The target's own resource tree is discarded (``REPLACE`` semantics), which
    is what cloning wants.  If ``resfile`` is given, the extracted resources are
    also written there.  Returns the number of resources copied.
    """
    with PEImage(source) as image:
        entries = image.entries()
    if not entries:
        raise PEError(f"{source} has no resources to copy")
    if resfile is not None:
        write_file(resfile, entries)
    with PEImage(target) as image:
        image.prepare_for_edit()
        image.merge(entries, REPLACE)
        image.save(output)
    return len(entries)
