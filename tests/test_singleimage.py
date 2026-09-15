import os
import struct

from bfforge import forge as forge_mod
from bfforge import singleimage as si
from bfforge.donor import Donor
from bfforge.target import Target


def test_roundtrip_synthetic():
    recs = si.with_trailer([
        si.Record("index.xml", b"<index/>"),
        si.Record("programmer.elf", b"\x7fELF" + b"\x00" * 5000),
        si.Record("xbl.elf", os.urandom(0x1000)),  # already page-aligned
        si.Record("gpt.bin", os.urandom(123)),
    ])
    blob = si.build(recs)
    back = si.parse(blob)
    assert [r.name for r in back] == [r.name for r in recs]
    assert [r.data for r in back] == [r.data for r in recs]
    # rebuilding the parsed records is a fixed point
    assert si.build(back) == blob


def test_header_layout():
    blob = si.build(si.with_trailer([si.Record("programmer.elf", b"abc")]))
    assert blob[:16] == si.MAGIC
    # first record header sits at 0x100; name at 0, size u64 at 0xf8
    assert blob[0x100:0x100 + 14] == b"programmer.elf"
    assert struct.unpack_from("<Q", blob, 0x100 + 0xF8)[0] == 3
    assert blob[0x200:0x203] == b"abc"


def test_forge_shape():
    donor = Donor(programmer=b"\x7fELF" + b"L" * 1000, recipes={}, cpu_name="SM_DIVAR", storage="UFS")
    target = Target(
        parts={"xbl.elf": b"x" * 200, "abl.elf": b"a" * 200},
        flash_map={"xbl": "xbl.elf", "abl": "abl.elf"},
        gpt=b"g" * 500,
        storage="emmc",
    )
    res = forge_mod.forge(donor, target)
    names = list(si.index(si.parse(res.singleimage)))
    assert names[:4] == ["index.xml", "pkg.xml", "default.xml", "programmer.elf"]
    assert "gpt.bin" in names and "xbl.elf" in names
    recipe = si.index(si.parse(res.singleimage))["default.xml"].decode()
    assert 'MemoryName="emmc"' in recipe  # target storage wins over donor's UFS
    assert any("storage" in w for w in res.warnings)  # emmc vs UFS mismatch flagged
