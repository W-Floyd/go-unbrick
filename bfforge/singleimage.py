"""Codec for Motorola's ``SINGLE_N_LONELY`` container.

Both ``singleimage.bin`` (a qboot blankflash) and ``bootloader.img`` (the packed
boot chain inside a stock firmware package) use this format, and the ``gpt.bin``
of a UFS device is itself one of these nested inside the stock package. One codec
handles all three.

Layout (reverse-engineered, round-trips byte-exact against real images):

    off 0x000  16B  magic "SINGLE_N_LONELY\0", rest of a 0x100 block zero
    then, per file, a record:
      off +0x000  0x100  header: name (NUL-terminated) at 0, u64 LE size at 0xf8
      off +0x100  size   content
                         padded with zeros up to the next 0x1000 boundary
    a final record named "LONELY_N_SINGLE" with size 0 marks the end.

The header carries no offset or checksum: position is implied by walking, and the
0x1000 content padding is the only alignment. Names live in the header's first
0xf8 bytes, so they cap at 247 bytes.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

MAGIC = b"SINGLE_N_LONELY\x00"
TRAILER = "LONELY_N_SINGLE"
HDR = 0x100
PAGE = 0x1000
_SIZE_OFF = HDR - 8


@dataclass
class Record:
    name: str
    data: bytes


def _pad(n: int) -> int:
    return (-n) % PAGE


def parse(blob: bytes) -> list[Record]:
    """Walk a container into records, including the trailing sentinel."""
    if blob[: len(MAGIC)] != MAGIC:
        raise ValueError("not a SINGLE_N_LONELY container")
    recs: list[Record] = []
    p = HDR
    while p + HDR <= len(blob):
        hdr = blob[p : p + HDR]
        name = hdr.split(b"\x00", 1)[0]
        if not name:  # blank header = past the end
            break
        size = struct.unpack_from("<Q", hdr, _SIZE_OFF)[0]
        data = blob[p + HDR : p + HDR + size]
        if len(data) != size:
            raise ValueError(f"record {name!r} truncated: want {size}, have {len(data)}")
        recs.append(Record(name.decode(), data))
        if name.decode() == TRAILER:
            break
        p += HDR + size + _pad(size)
    return recs


def build(recs: list[Record]) -> bytes:
    """Serialize records back into a container, appending the sentinel if absent."""
    out = bytearray(MAGIC + b"\x00" * (HDR - len(MAGIC)))
    saw_trailer = False
    for r in recs:
        nb = r.name.encode()
        if len(nb) > _SIZE_OFF:
            raise ValueError(f"name too long ({len(nb)} > {_SIZE_OFF}): {r.name}")
        hdr = bytearray(HDR)
        hdr[: len(nb)] = nb
        struct.pack_into("<Q", hdr, _SIZE_OFF, len(r.data))
        out += hdr + r.data + b"\x00" * _pad(len(r.data))
        saw_trailer = saw_trailer or r.name == TRAILER
    if not saw_trailer:
        hdr = bytearray(HDR)
        tb = TRAILER.encode()
        hdr[: len(tb)] = tb
        out += hdr
    return bytes(out)


def with_trailer(recs: list[Record]) -> list[Record]:
    """Return records with exactly one trailing sentinel."""
    body = [r for r in recs if r.name != TRAILER]
    return body + [Record(TRAILER, b"")]


def index(recs: list[Record]) -> dict[str, bytes]:
    """Name -> data, ignoring the sentinel. Last write wins on dupes."""
    return {r.name: r.data for r in recs if r.name != TRAILER}


def is_container(blob: bytes) -> bool:
    return blob[: len(MAGIC)] == MAGIC
