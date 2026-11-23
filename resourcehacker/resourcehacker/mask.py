"""Resource mask parsing, mirroring Resource Hacker's own parser.

Resource Hacker parses ``-mask`` as three positional comma-separated fields
(type, name, language).  The decompiled parser (``FUN_006dcc20`` in 5.1.8.360)
does the following, and this module reproduces it:

* the type is everything before the first comma,
* the name is everything between the first and second comma,
* the language is the entire remainder,
* type and name are uppercased with an ASCII-only fold before use,
* an empty field means "wildcard",
* the language is converted with ``StrToIntDef(remainder, 0xFFFF)``, so an
  absent or non-numeric remainder becomes "any language".

The last point is why metatwin's literal ``-mask ,,,`` selects everything: the
third comma lands in the language field, fails integer conversion and falls
back to the wildcard.

Resource Hacker requires at least two commas.  A one-comma mask such as
``ICON,MAINICON`` makes the binary exit with 0xFFFFFFFF, so that case is
rejected here too.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, FrozenSet, Optional, Union

ResourceId = Union[int, str]

_ASCII_LOWER = "abcdefghijklmnopqrstuvwxyz"
_ASCII_UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
_UPPER_TABLE = str.maketrans(_ASCII_LOWER, _ASCII_UPPER)

#: Resource Hacker's type-name aliases, mapped to the PE resource type ids they
#: select.  ``ICON`` implies the icon *group* as well: the binary warns "Icon
#: images cannot be manipulated directly, assumes IconGroup" and extracts both
#: the group and its images (measured: ``ICON,,`` yields 39 entries from a file
#: with 30 RT_ICON and 9 RT_GROUP_ICON).  ``CURSOR`` behaves the same way.
TYPE_ALIASES: Dict[str, FrozenSet[int]] = {
    "BITMAP": frozenset({2}),
    "CURSOR": frozenset({1, 12}),
    "CURSORGROUP": frozenset({1, 12}),
    "ICON": frozenset({3, 14}),
    "ICONGROUP": frozenset({3, 14}),
    "MENU": frozenset({4}),
    "DIALOG": frozenset({5}),
    "STRINGTABLE": frozenset({6}),
    "FONTDIR": frozenset({7}),
    "FONT": frozenset({8}),
    "ACCELERATORS": frozenset({9}),
    "RCDATA": frozenset({10}),
    "MESSAGETABLE": frozenset({11}),
    "VERSIONINFO": frozenset({16}),
    "DLGINCLUDE": frozenset({17}),
    "PLUGPLAY": frozenset({19}),
    "VXD": frozenset({20}),
    "ANI CURSOR": frozenset({21}),
    "ANI ICON": frozenset({22}),
    "HTML": frozenset({23}),
    "MANIFEST": frozenset({24}),
}

_ANY = None


class MaskError(ValueError):
    """Raised when a mask cannot be parsed or is syntactically invalid."""


def upper_ascii(text: str) -> str:
    """Uppercase ASCII letters only, leaving every other character alone.

    This mirrors ``FUN_00422010``: it tests ``ch - 0x61 < 0x1a`` and XORs
    ``0x20``.  Non-ASCII names therefore stay case-sensitive.
    """
    return text.translate(_UPPER_TABLE)


def _parse_field(raw: str) -> Optional[ResourceId]:
    text = raw.strip()
    if text in ("", "*"):
        return _ANY
    if text.isdigit():
        value = int(text, 10)
        if value > 0xFFFF:
            raise MaskError(f"resource id {value} does not fit in 16 bits")
        return value
    return upper_ascii(text)


def _parse_language(raw: str) -> Optional[int]:
    text = raw.strip()
    if text in ("", "*"):
        return _ANY
    try:
        value = int(text, 10)
    except ValueError:
        # StrToIntDef falls back to 0xFFFF, which is "any language".
        return _ANY
    if not 0 <= value <= 0xFFFF:
        raise MaskError(f"language id {value} does not fit in 16 bits")
    return value


@dataclass(frozen=True)
class Mask:
    """A parsed ``-mask`` value; ``None`` in a field means wildcard."""

    type: Optional[ResourceId] = _ANY
    name: Optional[ResourceId] = _ANY
    language: Optional[int] = _ANY

    def matches(self, type_id: ResourceId, name_id: ResourceId, language: int) -> bool:
        return (
            self._type_matches(type_id)
            and self._name_matches(name_id)
            and (self.language is None or self.language == language)
        )

    def _type_matches(self, type_id: ResourceId) -> bool:
        if self.type is None:
            return True
        if isinstance(self.type, int):
            return type_id == self.type
        alias = TYPE_ALIASES.get(self.type)
        if alias is not None:
            return type_id in alias
        # Unaliased names (TEMPLATES, TEXT, ...) match string types only.
        return isinstance(type_id, str) and upper_ascii(type_id) == self.type

    def _name_matches(self, name_id: ResourceId) -> bool:
        if self.name is None:
            return True
        if isinstance(self.name, int):
            return name_id == self.name
        return isinstance(name_id, str) and upper_ascii(name_id) == self.name


def parse_mask(text: Optional[str]) -> Mask:
    """Parse a ``-mask`` value the way Resource Hacker does."""
    if text is None:
        return Mask()
    if text.count(",") < 2:
        raise MaskError(
            f"invalid resource mask {text!r}: three comma-separated fields "
            "(type,name,language) are required"
        )
    type_text, rest = text.split(",", 1)
    name_text, language_text = rest.split(",", 1)
    return Mask(
        type=_parse_field(type_text),
        name=_parse_field(name_text),
        language=_parse_language(language_text),
    )


def resource_type_name(type_id: ResourceId) -> str:
    """Render a resource type for logs: numeric ids stay numeric."""
    return str(type_id)


def resource_name(name_id: ResourceId) -> str:
    """Render a resource name for logs: numeric ids stay numeric."""
    return str(name_id)
