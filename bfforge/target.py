"""Harvest the target device's own bootloader partitions and GPT.

These come from the target's *own* stock firmware -- never the donor's -- because
only the loader is cross-device; the partitions and partition table are unique to
the target model (and, for the GPT, to the target unit's storage). Two sources are
supported: the packed ``bootloader.img`` from a stock package, or a directory of
raw per-partition dumps (e.g. ``xbl_a.img`` pulled off the live device), which is
the most faithful source for a specific unit.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from . import singleimage as si

# Recipe partition label -> the filename qboot expects inside the singleimage.
# Derived from Motorola stock bootloader.default.xml; the tool prefers the
# target's own map when present and falls back to this.
DEFAULT_MAP = {
    "abl": "abl.elf",
    "xbl": "xbl.elf",
    "xbl_config": "xbl_config.elf",
    "qupfw": "qupfw.elf",
    "rpm": "rpm.mbn",
    "tz": "tz.mbn",
    "hyp": "hyp.mbn",
    "devcfg": "devcfg.mbn",
    "keymaster": "keymaster.mbn",
    "storsec": "storsec.mbn",
    "prov": "prov64.mbn",
    "uefisecapp": "uefi_sec.mbn",
}


@dataclass
class Target:
    parts: dict[str, bytes]  # filename (as flashed) -> bytes
    flash_map: dict[str, str]  # partition label -> filename
    gpt: bytes | None = None  # gpt.bin (kept whole; qboot flashes it as-is)
    storage: str | None = None  # emmc / ufs, if determinable
    source: str = ""


def _flash_map_from_recipe(recipe_xml: bytes) -> dict[str, str]:
    txt = recipe_xml.decode("utf-8", "replace")
    out: dict[str, str] = {}
    for m in re.finditer(r'partition="([^"]+)"\s+filename="([^"]+)"', txt):
        label, fn = m.group(1), m.group(2)
        if label != "partition":  # "partition" is the GPT pseudo-target
            out[re.sub(r"_[ab]$", "", label)] = fn
    return out


def _infer_storage(gpt: bytes | None, recipe_xml: bytes) -> str | None:
    if recipe_xml:
        m = re.search(r'storage\.type="([^"]+)"', recipe_xml.decode("utf-8", "replace"))
        if m:
            return m.group(1).lower()
    if gpt is not None and si.is_container(gpt):
        names = si.index(si.parse(gpt))
        luns = [n for n in names if re.fullmatch(r"gpt_main\d+\.bin", n)]
        # >1 LUN GPT is a UFS trait; a single main GPT is typical of eMMC.
        return "ufs" if len(luns) > 1 else "emmc"
    return None


def from_bootloader_img(img: bytes, gpt: bytes | None = None) -> Target:
    recs = si.index(si.parse(img))
    recipe = next((recs[n] for n in recs if n.endswith("default.xml")), b"")
    flash_map = _flash_map_from_recipe(recipe) or dict(DEFAULT_MAP)
    parts = {fn: recs[fn] for fn in flash_map.values() if fn in recs}
    return Target(
        parts=parts,
        flash_map=flash_map,
        gpt=gpt,
        storage=_infer_storage(gpt, recipe),
        source="bootloader.img",
    )


def from_dumps(dump_dir: str | Path, slot: str = "a", gpt: bytes | None = None) -> Target:
    """Build a target from raw per-partition dumps like ``xbl_a.img``."""
    d = Path(dump_dir)
    parts: dict[str, bytes] = {}
    flash_map: dict[str, str] = {}
    for label, fn in DEFAULT_MAP.items():
        for cand in (f"{label}_{slot}.img", f"{label}.img"):
            f = d / cand
            if f.exists():
                parts[fn] = f.read_bytes()
                flash_map[label] = fn
                break
    if gpt is None:
        for cand in ("gpt.bin", "gpt_main0.img", "gpt.img"):
            if (d / cand).exists():
                gpt = (d / cand).read_bytes()
                break
    return Target(
        parts=parts,
        flash_map=flash_map,
        gpt=gpt,
        storage=_infer_storage(gpt, b""),
        source=f"dumps:{d}",
    )
