import os
import struct
import sys

import pytest

from resourcehacker.cli import UsageError, main, parse_switches

WINDOWS_SAMPLE = r"C:\Windows\System32\where.exe"


def test_basic_switches():
    assert parse_switches(["-open", "a.exe", "-action", "extract"]) == {
        "open": "a.exe",
        "action": "extract",
    }


def test_unambiguous_abbreviation():
    assert parse_switches(["-res", "x.res"]) == {"resource": "x.res"}


def test_ambiguous_abbreviation_is_rejected():
    with pytest.raises(UsageError):
        parse_switches(["-s", "x"])


def test_unknown_switch_is_rejected():
    with pytest.raises(UsageError):
        parse_switches(["-nope", "x"])


def test_missing_value_is_rejected():
    with pytest.raises(UsageError):
        parse_switches(["-open"])


def test_positional_argument_is_rejected():
    with pytest.raises(UsageError):
        parse_switches(["input.exe"])


def test_help_returns_zero(capsys):
    assert main(["-help"]) == 0
    assert "Usage:" in capsys.readouterr().out


def test_missing_action_fails(tmp_path):
    log = tmp_path / "log.txt"
    code = main(["-open", str(tmp_path / "a.exe"), "-log", str(log)])
    assert code != 0
    assert "Failed!" in log.read_text(encoding="utf-16-le")


def test_unsupported_action_fails(tmp_path):
    log = tmp_path / "log.txt"
    code = main(
        [
            "-open",
            str(tmp_path / "a.exe"),
            "-save",
            str(tmp_path / "b.exe"),
            "-action",
            "compile",
            "-log",
            str(log),
        ]
    )
    assert code != 0
    assert "not implemented" in log.read_text(encoding="utf-16-le")


@pytest.mark.skipif(
    not os.path.exists(WINDOWS_SAMPLE), reason="needs a Windows PE sample"
)
def test_replace_installs_the_source_tree_exactly(tmp_path):
    """The cloning action must leave nothing of the target's resources behind."""
    from resourcehacker.pelayer import PEImage

    def leaves(path):
        with PEImage(str(path)) as image:
            entries = [
                (entry.type_id, entry.name_id, entry.language, entry.data)
                for entry in image.entries()
            ]
        return sorted(entries, key=lambda item: (str(item[0]), str(item[1]), item[2]))

    source = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "notepad.exe")
    if not os.path.exists(source):
        pytest.skip("needs notepad.exe as a second sample")

    res = tmp_path / "source.res"
    assert (
        main(
            [
                "-open",
                source,
                "-action",
                "extract",
                "-mask",
                ",,,",
                "-save",
                str(res),
                "-log",
                str(tmp_path / "extract.log"),
            ]
        )
        == 0
    )

    out = tmp_path / "cloned.exe"
    assert (
        main(
            [
                "-open",
                WINDOWS_SAMPLE,
                "-save",
                str(out),
                "-resource",
                str(res),
                "-action",
                "replace",
                "-log",
                str(tmp_path / "replace.log"),
            ]
        )
        == 0
    )

    assert leaves(out) == leaves(source)


@pytest.mark.skipif(
    not os.path.exists(WINDOWS_SAMPLE), reason="needs a Windows PE sample"
)
def test_extract_and_merge_round_trip(tmp_path):
    extracted = tmp_path / "out.res"
    log = tmp_path / "extract.log"

    assert (
        main(
            [
                "-open",
                WINDOWS_SAMPLE,
                "-action",
                "extract",
                "-mask",
                ",,,",
                "-save",
                str(extracted),
                "-log",
                str(log),
            ]
        )
        == 0
    )

    raw = extracted.read_bytes()
    assert len(raw) > 0x20
    assert raw[:8] == struct.pack("<II", 0, 0x20)

    log_bytes = log.read_bytes()
    assert not log_bytes.startswith(b"\xff\xfe")
    assert "Success!" in log_bytes.decode("utf-16-le")

    merged = tmp_path / "merged.exe"
    merge_log = tmp_path / "merge.log"
    assert (
        main(
            [
                "-open",
                WINDOWS_SAMPLE,
                "-save",
                str(merged),
                "-resource",
                str(extracted),
                "-action",
                "addoverwrite",
                "-log",
                str(merge_log),
            ]
        )
        == 0
    )
    assert merged.exists()
