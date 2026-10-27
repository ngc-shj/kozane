"""A minimal flash.bin for the host tests (M7 plan C4): BL1 stand-in bytes,
then at measure.FIP_OFFSET a FIP holding the given entries, laid out as
TF-A's fiptool does (ToC header, entries, a null-UUID terminator, then the
payloads)."""

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2] / "tools"))
import measure  # noqa: E402


def payloads() -> list:
    """(uuid, bytes) of a well-formed FIP's three measured images."""
    return [(uuid, f"{name} image ".encode() * (i + 3)) for i, (name, uuid) in enumerate(measure.FIP_MEASURED)]


def fip(entries: list) -> bytes:
    toc = measure.FIP_HEADER.pack(measure.FIP_TOC_NAME, 0, 0)
    offset = measure.FIP_HEADER.size + measure.FIP_ENTRY.size * (len(entries) + 1)
    body = b""
    for uuid, data in entries:
        toc += measure.FIP_ENTRY.pack(uuid, offset + len(body), len(data), 0)
        body += data
    toc += measure.FIP_ENTRY.pack(bytes(16), offset + len(body), 0, 0)
    return toc + body


def flash(entries: list = None) -> bytes:
    return b"BL1" + bytes(measure.FIP_OFFSET - 3) + fip(payloads() if entries is None else entries)
