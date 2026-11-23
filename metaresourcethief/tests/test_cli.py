import os

import pytest
import sigthief

from metaresourcethief.cli import main
from resourcehacker.pelayer import PEImage

SIGNED = r"C:\Windows\explorer.exe"
UNSIGNED = r"C:\Windows\System32\where.exe"
SMALL = r"C:\Windows\System32\notepad.exe"

needs_samples = pytest.mark.skipif(
    not all(os.path.exists(path) for path in (SIGNED, UNSIGNED, SMALL)),
    reason="needs a signed source, a small resource source and a target PE",
)


def _leaves(path):
    with PEImage(str(path)) as image:
        entries = [
            (entry.type_id, entry.name_id, entry.language, entry.data)
            for entry in image.entries()
        ]
    return sorted(entries, key=lambda item: (str(item[0]), str(item[1]), item[2]))


def _certificate(path):
    """Read an embedded certificate table with SigThief's own code."""
    return sigthief.copyCert(str(path))


def test_missing_input_is_reported(tmp_path, capsys):
    code = main(
        ["-s", str(tmp_path / "nope.exe"), "-t", UNSIGNED, "-o", str(tmp_path / "out.exe")]
    )
    assert code == 1
    assert "does not exist" in capsys.readouterr().err


@needs_samples
def test_no_metadata_without_sign_is_refused(tmp_path, capsys):
    code = main(
        ["-s", SMALL, "-t", UNSIGNED, "-o", str(tmp_path / "out.exe"), "--no-metadata"]
    )
    assert code == 1
    assert "nothing to copy" in capsys.readouterr().err


@needs_samples
def test_output_must_differ_from_inputs(tmp_path, capsys):
    code = main(["-s", SMALL, "-t", UNSIGNED, "-o", UNSIGNED])
    assert code == 1
    assert "differ" in capsys.readouterr().err


@needs_samples
def test_metadata_only(tmp_path):
    out = tmp_path / "out.exe"
    assert main(["-s", SMALL, "-t", UNSIGNED, "-o", str(out)]) == 0
    assert _leaves(out) == _leaves(SMALL)


@needs_samples
def test_metadata_and_signature(tmp_path):
    out = tmp_path / "out.exe"
    assert main(["-s", SIGNED, "-t", UNSIGNED, "-o", str(out), "--sign"]) == 0
    assert _leaves(out) == _leaves(SIGNED)
    assert _certificate(out) == _certificate(SIGNED)


@needs_samples
def test_signature_only(tmp_path):
    out = tmp_path / "out.exe"
    args = ["-s", SIGNED, "-t", UNSIGNED, "-o", str(out), "--sign", "--no-metadata"]
    assert main(args) == 0
    assert _leaves(out) == _leaves(UNSIGNED)
    assert _certificate(out) == _certificate(SIGNED)


@needs_samples
def test_unsigned_source_with_sign_is_refused(tmp_path, capsys):
    code = main(["-s", UNSIGNED, "-t", SMALL, "-o", str(tmp_path / "out.exe"), "--sign"])
    assert code == 1
    assert "no embedded signature" in capsys.readouterr().err
    assert not (tmp_path / "out.exe").exists()