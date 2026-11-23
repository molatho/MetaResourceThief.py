"""Signature copying, delegated to the upstream SigThief module.

``sigthief`` is installed as a real distribution (built from the ``packaging``
project, which packages the ``packaging/sigthief`` submodule), so this is a
plain import: no path juggling, no subprocess.
"""

from __future__ import annotations

import contextlib
import io
from pathlib import Path

import sigthief


class SignatureError(RuntimeError):
    """Raised when the source has no embedded signature."""


def copy_signature(source: Path, target: Path, output: Path) -> int:
    """Copy ``source``'s certificate table onto ``target``, writing ``output``.

    Returns the size of the transplanted blob.  SigThief's chatter is captured
    so callers can report the result in their own words.
    """
    transcript = io.StringIO()
    try:
        with contextlib.redirect_stdout(transcript):
            certificate = sigthief.copyCert(str(source))
    except SystemExit:
        raise SignatureError("source has no embedded signature") from None
    with contextlib.redirect_stdout(transcript):
        sigthief.writeCert(certificate, str(target), str(output))
    return len(certificate)
