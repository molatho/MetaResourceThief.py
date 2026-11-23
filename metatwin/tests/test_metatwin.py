import os

import pytest
import sigthief

from metatwin.cli import main

SOURCE = r"C:\Windows\explorer.exe"
TARGET = r"C:\Windows\System32\where.exe"

needs_samples = pytest.mark.skipif(
    not (os.path.exists(SOURCE) and os.path.exists(TARGET)),
    reason="needs a signed source and a target PE",
)


def _certificate(path):
    """Read an embedded certificate table with SigThief's own code."""
    return sigthief.copyCert(str(path))


def test_missing_input_is_reported(tmp_path, capsys):
    assert main(["-s", str(tmp_path / "nope.exe"), "-t", TARGET, "-o", str(tmp_path)]) == 1
    assert "does not exist" in capsys.readouterr().err


@needs_samples
def test_pipeline_produces_a_clone(tmp_path):
    assert main(["-s", SOURCE, "-t", TARGET, "-o", str(tmp_path), "--sign"]) == 0

    outputs = sorted(tmp_path.rglob("*signed_where.exe"))
    assert outputs, "no signed output produced"
    clone = outputs[0]

    from resourcehacker.pelayer import PEImage

    def leaves(path):
        with PEImage(str(path)) as image:
            entries = [
                (entry.type_id, entry.name_id, entry.language, entry.data)
                for entry in image.entries()
            ]
        return sorted(entries, key=lambda item: (str(item[0]), str(item[1]), item[2]))

    assert leaves(clone) == leaves(SOURCE)
    assert _certificate(clone) == _certificate(SOURCE)


@needs_samples
def test_timestamps_follow_the_source(tmp_path):
    assert main(["-s", SOURCE, "-t", TARGET, "-o", str(tmp_path)]) == 0
    outputs = sorted(tmp_path.rglob("*_twin.exe"))
    assert outputs
    source_stat = os.stat(SOURCE)
    clone_stat = os.stat(outputs[0])
    assert int(clone_stat.st_mtime) == int(source_stat.st_mtime)
