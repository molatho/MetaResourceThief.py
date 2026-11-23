import pytest

from resourcehacker.mask import MaskError, parse_mask


def test_triple_comma_selects_everything():
    mask = parse_mask(",,,")
    assert (mask.type, mask.name, mask.language) == (None, None, None)


def test_two_commas_are_enough():
    mask = parse_mask(",,")
    assert (mask.type, mask.name, mask.language) == (None, None, None)


def test_one_comma_is_rejected():
    # The original binary exits 0xFFFFFFFF for this: a validator apart from the
    # parser insists on two commas.
    with pytest.raises(MaskError):
        parse_mask("ICON,MAINICON")


def test_star_is_a_wildcard():
    mask = parse_mask("*,*,*")
    assert (mask.type, mask.name, mask.language) == (None, None, None)


def test_type_names_are_case_folded():
    assert parse_mask("templates,,").type == "TEMPLATES"
    assert parse_mask("IcOnGroup,,").type == "ICONGROUP"


def test_numeric_type():
    assert parse_mask("24,,").type == 24


def test_language_is_parsed():
    assert parse_mask("ICON,MAINICON,1033").language == 1033


def test_non_numeric_language_becomes_any():
    # StrToIntDef(remainder, 0xFFFF): ",,," works because of this.
    assert parse_mask("ICON,MAINICON,xyz").language is None


def test_icon_alias_matches_image_and_group():
    mask = parse_mask("ICON,,")
    assert mask.matches(3, 1, 0)
    assert mask.matches(14, "MAINICON", 1033)
    assert not mask.matches(2, 1, 0)


def test_cursor_alias_matches_image_and_group():
    mask = parse_mask("CURSOR,,")
    assert mask.matches(1, 1, 0)
    assert mask.matches(12, "ARROW", 0)


def test_version_must_be_spelled_versioninfo():
    assert not parse_mask("VERSION,,").matches(16, 1, 0)
    assert parse_mask("VERSIONINFO,,").matches(16, 1, 0)


def test_string_must_be_spelled_stringtable():
    assert not parse_mask("STRING,,").matches(6, 1, 0)
    assert parse_mask("STRINGTABLE,,").matches(6, 1, 0)


def test_custom_string_type():
    mask = parse_mask("TEMPLATES,,")
    assert mask.matches("TEMPLATES", "ACCELERATORS", 0)
    assert not mask.matches("TEXT", "X", 0)


def test_named_resource_match_is_case_insensitive():
    mask = parse_mask(",mainicon,")
    assert mask.matches(14, "MAINICON", 0)
    assert mask.matches(14, "mainicon", 0)


def test_language_filter():
    mask = parse_mask(",,1031")
    assert mask.matches(3, 1, 1031)
    assert not mask.matches(3, 1, 0)
