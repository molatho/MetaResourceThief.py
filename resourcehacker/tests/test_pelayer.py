import struct

from resourcehacker.pelayer import (
    _GROUP_HEADER_SIZE,
    _GROUP_ENTRY_SIZE,
    _GROUP_ENTRY_ID_OFFSET,
    _next_free_id,
    _patch_group_payload,
    PEImage,
)
from resourcehacker.resfile import ResourceEntry


def _group_payload(ids):
    payload = bytearray(struct.pack("<HHH", 0, 1, len(ids)))
    for image_id in ids:
        entry = bytearray(_GROUP_ENTRY_SIZE)
        struct.pack_into("<H", entry, _GROUP_ENTRY_ID_OFFSET, image_id)
        payload += entry
    return bytes(payload)


def _group_ids(payload):
    _r, _t, count = struct.unpack_from("<HHH", payload, 0)
    return [
        struct.unpack_from(
            "<H", payload, _GROUP_HEADER_SIZE + i * _GROUP_ENTRY_SIZE + _GROUP_ENTRY_ID_OFFSET
        )[0]
        for i in range(count)
    ]


def test_patch_group_rewrites_ids():
    payload = _group_payload([1, 2, 3])
    patched = _patch_group_payload(payload, 3, {(3, 1): 10, (3, 3): 11})
    assert _group_ids(patched) == [10, 2, 11]


def test_patch_group_keeps_other_bytes():
    payload = _group_payload([1])
    patched = _patch_group_payload(payload, 3, {(3, 1): 9})
    assert len(patched) == len(payload)
    assert patched[:_GROUP_HEADER_SIZE] == payload[:_GROUP_HEADER_SIZE]
    assert patched[_GROUP_HEADER_SIZE : _GROUP_HEADER_SIZE + 12] == payload[
        _GROUP_HEADER_SIZE : _GROUP_HEADER_SIZE + 12
    ]


def test_patch_group_tolerates_truncation():
    payload = _group_payload([1])[:-4]
    assert _patch_group_payload(payload, 3, {(3, 1): 9})


def test_next_free_id():
    assert _next_free_id({}, 3) == 1
    assert _next_free_id({3: {1: {}, 7: {}, "MAINICON": {}}}, 3) == 8


def test_renumber_moves_images_and_patches_groups():
    tree = {3: {1: {0: b"old"}, 5: {0: b"old2"}}}
    entries = [
        ResourceEntry(3, 1, 1033, b"new-image"),
        ResourceEntry(14, "MAINICON", 1033, _group_payload([1])),
    ]
    result = PEImage._renumber_images(None, tree, entries)

    image, group = result
    assert image.name_id == 6  # max existing id (5) + 1
    assert image.language == 0
    assert group.language == 0
    assert _group_ids(group.data) == [6]


def test_renumber_leaves_non_image_resources_alone():
    tree = {}
    entries = [ResourceEntry(10, "HELLO", 1033, b"data")]
    assert PEImage._renumber_images(None, tree, entries) == entries
