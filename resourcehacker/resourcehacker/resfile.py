"""Reader and writer for Microsoft compiled resource files (``.res``).

The layout is the one documented for ``RESOURCEHEADER`` and confirmed against
Resource Hacker 5.1.8.360's own output:

    entry:
        DWORD  DataSize                 size of the payload that follows
        DWORD  HeaderSize               offset from the entry start to the payload,
                                        *including* these two DWORDs
        TYPE                            ordinal (0xFFFF + WORD) or UTF-16 string
        NAME                            same encoding
        BYTE[] padding                  to a DWORD boundary
        DWORD  DataVersion
        WORD   MemoryFlags
        WORD   LanguageId
        DWORD  Version
        DWORD  Characteristics
        BYTE[] payload                  padded to a DWORD boundary

Three details that trip up hand-rolled parsers, all confirmed by hexdumping a
``.res`` that Resource Hacker wrote itself:

* ``HeaderSize`` counts its own eight bytes, so the payload begins at
  ``entry_start + HeaderSize``.
* There is **no** padding between TYPE and NAME: a ten-byte type such as
  ``TEXT`` is followed immediately by the name, which therefore starts at a
  two-mod-four offset.
* Padding after NAME aligns the **absolute file offset**, not the field length.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import List, Optional, Tuple, Union

ResourceId = Union[int, str]

#: Size of the empty entry that every ``.res`` file begins with.
NULL_ENTRY_SIZE = 0x20

#: Memory flags Resource Hacker writes on entries it extracts (MOVEABLE | PURE |
#: DISCARDABLE).  They are inert for our purposes but preserved for fidelity.
DEFAULT_MEMORY_FLAGS = 0x1030

_ORDINAL_MARKER = 0xFFFF


class ResError(ValueError):
    """Raised when a ``.res`` file is malformed or cannot be represented."""


@dataclass
class ResourceEntry:
    """One resource in a ``.res`` file or a PE resource tree."""

    type_id: ResourceId
    name_id: ResourceId
    language: int
    data: bytes
    memory_flags: int = DEFAULT_MEMORY_FLAGS

    def label(self) -> str:
        return f"{self.type_id},{self.name_id},{self.language}"


def _check_id(value: ResourceId) -> None:
    if isinstance(value, bool) or not isinstance(value, (int, str)):
        raise ResError(f"resource id must be an int or str, not {type(value)!r}")
    if isinstance(value, int) and not 0 <= value <= 0xFFFF:
        raise ResError(f"resource id {value} does not fit in 16 bits")


def _pack_id(value: ResourceId, offset: int, pad: bool) -> bytes:
    """Encode a TYPE/NAME member.  ``offset`` is its absolute file position."""
    _check_id(value)
    if isinstance(value, int):
        return struct.pack("<HH", _ORDINAL_MARKER, value)
    raw = value.encode("utf-16-le") + b"\x00\x00"
    if pad:
        raw += b"\x00" * (-(offset + len(raw)) % 4)
    return raw


def _read_id(blob: bytes, pos: int, end: int, pad: bool) -> Tuple[ResourceId, int]:
    if pos + 2 > end:
        raise ResError(f"truncated TYPE/NAME at offset {pos:#x}")
    (first,) = struct.unpack_from("<H", blob, pos)
    if first == _ORDINAL_MARKER:
        if pos + 4 > end:
            raise ResError(f"truncated ordinal at offset {pos:#x}")
        (value,) = struct.unpack_from("<H", blob, pos + 2)
        return value, pos + 4
    chars: List[str] = []
    while True:
        if pos + 2 > end:
            raise ResError(f"unterminated name string at offset {pos:#x}")
        (unit,) = struct.unpack_from("<H", blob, pos)
        pos += 2
        if unit == 0:
            break
        chars.append(chr(unit))
    if pad:
        pos += (-pos) % 4
    return "".join(chars), pos


def encode(entries: List[ResourceEntry]) -> bytes:
    """Serialize entries to the bytes of a ``.res`` file."""
    out = bytearray()
    # The mandatory empty entry: type 0 / name 0, no payload, 0x20-byte header.
    out += struct.pack("<II", 0, NULL_ENTRY_SIZE)
    out += _pack_id(0, len(out), pad=False)
    out += _pack_id(0, len(out), pad=False)
    out += b"\x00" * 16

    for entry in entries:
        start = len(out)
        type_field = _pack_id(entry.type_id, start + 8, pad=False)
        name_field = _pack_id(entry.name_id, start + 8 + len(type_field), pad=True)
        body = type_field + name_field
        body += struct.pack(
            "<IHHII",
            0,  # DataVersion
            entry.memory_flags & 0xFFFF,
            entry.language & 0xFFFF,
            0,  # Version
            0,  # Characteristics
        )
        out += struct.pack("<II", len(entry.data), 8 + len(body))
        out += body
        out += entry.data
        out += b"\x00" * (-len(out) % 4)
    return bytes(out)


def decode(blob: bytes) -> List[ResourceEntry]:
    """Parse a ``.res`` file, skipping the leading empty entry."""
    entries: List[ResourceEntry] = []
    pos = 0
    first = True
    while pos + 8 <= len(blob):
        data_size, header_size = struct.unpack_from("<II", blob, pos)
        if header_size < 8:
            raise ResError(f"invalid HeaderSize {header_size:#x} at offset {pos:#x}")
        header_end = pos + header_size
        if header_end > len(blob):
            raise ResError(f"entry header overruns file at offset {pos:#x}")

        type_id, cursor = _read_id(blob, pos + 8, header_end, pad=False)
        name_id, cursor = _read_id(blob, cursor, header_end, pad=True)
        if cursor + 16 > header_end:
            raise ResError(f"truncated entry header at offset {pos:#x}")
        _version, flags, language, _value_version, _chars = struct.unpack_from(
            "<IHHII", blob, cursor
        )

        payload_end = header_end + data_size
        if payload_end > len(blob):
            raise ResError(f"entry payload overruns file at offset {pos:#x}")
        payload = blob[header_end:payload_end]

        is_null_entry = first and data_size == 0 and (type_id, name_id) == (0, 0)
        first = False
        if not is_null_entry:
            entries.append(
                ResourceEntry(
                    type_id=type_id,
                    name_id=name_id,
                    language=language,
                    data=payload,
                    memory_flags=flags,
                )
            )

        pos = payload_end + (-payload_end % 4)

    return entries


def read_file(path: str) -> List[ResourceEntry]:
    with open(path, "rb") as handle:
        return decode(handle.read())


def write_file(path: str, entries: List[ResourceEntry]) -> None:
    with open(path, "wb") as handle:
        handle.write(encode(entries))
