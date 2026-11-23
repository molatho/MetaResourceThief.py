import struct

import pytest

from resourcehacker.resfile import (
    DEFAULT_MEMORY_FLAGS,
    NULL_ENTRY_SIZE,
    ResourceEntry,
    ResError,
    decode,
    encode,
)


def test_empty_file_is_just_the_null_entry():
    blob = encode([])
    assert len(blob) == NULL_ENTRY_SIZE
    data_size, header_size = struct.unpack_from("<II", blob, 0)
    assert (data_size, header_size) == (0, 0x20)
    assert blob[8:12] == b"\xff\xff\x00\x00"  # type ordinal 0
    assert blob[12:16] == b"\xff\xff\x00\x00"  # name ordinal 0


def test_round_trip_mixed_ids():
    entries = [
        ResourceEntry(10, "HELLO", 1033, b"abc"),
        ResourceEntry("TEXT", "CMDLINE1", 0, b"\xff\xfeh\x00i\x00"),
        ResourceEntry(3, 1, 1033, b"\x00" * 7),
    ]
    decoded = decode(encode(entries))
    assert decoded == entries


def test_header_size_includes_its_own_bytes():
    entry = ResourceEntry(10, "N", 0, b"xyz")
    blob = encode([entry])
    data_size, header_size = struct.unpack_from("<II", blob, 0x20)
    assert data_size == 3
    assert blob[0x20 + header_size : 0x20 + header_size + 3] == b"xyz"


def test_type_field_is_not_padded():
    # "TEXT" is ten bytes, so the name must begin at 0x32, not 0x34.
    entry = ResourceEntry("TEXT", "X", 0, b"")
    blob = encode([entry])
    assert blob[0x28:0x32] == "TEXT".encode("utf-16-le") + b"\x00\x00"
    assert blob[0x32:0x34] == "X".encode("utf-16-le")


def test_name_padding_aligns_the_absolute_offset():
    # Name "X" is four bytes ending at 0x36, so two pad bytes take the header
    # block to 0x38.
    entry = ResourceEntry("TEXT", "X", 0, b"")
    blob = encode([entry])
    flags_at = 0x38
    (_version, flags, language, _vv, _chars) = struct.unpack_from("<IHHII", blob, flags_at)
    assert flags == DEFAULT_MEMORY_FLAGS
    assert language == 0


def test_payload_is_padded_to_4_bytes():
    blob = encode([ResourceEntry(10, 1, 0, b"a")])
    assert len(blob) % 4 == 0


def test_odd_payload_round_trips():
    entry = ResourceEntry(10, 1, 0, b"\x01\x02\x03")
    assert decode(encode([entry]))[0].data == b"\x01\x02\x03"


def test_truncated_file_is_rejected():
    blob = encode([ResourceEntry(10, 1, 0, b"abcdef")])
    # Cut into the payload, not just the padding.
    with pytest.raises(ResError):
        decode(blob[:-4])


def test_reserved_entry_is_skipped():
    blob = encode([ResourceEntry(10, 1, 0, b"x")])
    assert len(decode(blob)) == 1


def test_large_language_ids_survive():
    entry = ResourceEntry(10, 1, 0xFFFF, b"")
    assert decode(encode([entry]))[0].language == 0xFFFF
