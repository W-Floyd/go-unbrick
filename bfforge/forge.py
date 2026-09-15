"""Assemble a target blankflash from a donor's signed loader and the target's images.

The output ``singleimage.bin`` carries:

    index.xml, pkg.xml, default.xml   qboot recipe (generated for the target)
    programmer.elf                    the donor's signed Firehose loader
    <target bootloader partitions>    the target's own images
    gpt.bin                           the target's own partition table
    LONELY_N_SINGLE                   end sentinel

By default the recipe is a *minimal restore*: flash GPT + the boot chain, with no
storage re-provisioning. Re-provisioning (the donor's ``<ufs>`` LUN block) is
device- and storage-specific and can worsen a brick, so it is opt-in only.
"""

from __future__ import annotations

from dataclasses import dataclass

from . import singleimage as si
from .donor import Donor
from .target import Target

BOOT_ORDER = [  # flash order used by Motorola stock recipes (xbl last)
    "abl", "devcfg", "hyp", "keymaster", "tz", "storsec",
    "prov", "rpm", "qupfw", "uefisecapp", "xbl_config", "xbl",
]

BLANK_FLASH_BAT = "@echo off\r\nqboot.exe %* fastboot singleimage.bin\r\n"
BLANK_FLASH_SH = "#!/bin/sh\nexec \"$(dirname \"$0\")/qboot\" \"$@\" fastboot singleimage.bin\n"


@dataclass
class ForgeResult:
    singleimage: bytes
    aux: dict[str, bytes]  # qboot binaries + blank-flash scripts
    warnings: list[str]


def _index_xml(cpu: str, storage: str) -> bytes:
    return (
        '<?xml version="1.0"?>\n<index>\n'
        f'\t<board id="440" name="{cpu}" storage.type="{storage.upper()}" />\n'
        f'\t<package compatible="protocol:qboot cpu.name:{cpu}" filename="pkg.xml"/>\n'
        "</index>\n"
    ).encode()


def _pkg_xml() -> bytes:
    return (
        '<?xml version="1.0"?>\n<package>\n'
        '    <programmer filename="programmer.elf"/>\n'
        '    <recipe filename="default.xml"/>\n</package>\n'
    ).encode()


def _default_xml(target: Target, slot: str, storage: str, provision: bytes | None) -> bytes:
    lines = ['<?xml version="1.0" ?>', "<recipe>"]
    if provision:
        lines.append("\t<!-- provisioning supplied via --provision-from -->")
        lines.append(provision.decode("utf-8", "replace").strip())
    else:
        lines.append(f'\t<configure MemoryName="{storage}" SkipStorageInit="1"/>')
    lines.append('\t<setbootablestoragedrive value="1"/>')
    lines.append('\t<print what="Flashing GPT..."/>')
    lines.append('\t<flash partition="partition" filename="gpt.bin" verbose="true"/>')
    lines.append('\t<storage operation="reinit"/>')
    lines.append('\t<print what="Flashing bootloader..."/>')
    for label in BOOT_ORDER:
        fn = target.flash_map.get(label)
        if fn and fn in target.parts:
            lines.append(f'\t<flash partition="{label}_{slot}" filename="{fn}" verbose="true"/>')
    lines.append("</recipe>\n")
    return "\n".join(lines).encode()


def forge(
    donor: Donor,
    target: Target,
    slot: str = "a",
    storage: str | None = None,
    provision: bytes | None = None,
) -> ForgeResult:
    warnings: list[str] = []
    storage = (storage or target.storage or donor.storage or "emmc").lower()

    if donor.storage and target.storage and donor.storage.lower() != target.storage.lower():
        warnings.append(
            f"donor storage ({donor.storage}) != target storage ({target.storage}); "
            "using target's. Verify the recipe's <configure MemoryName> is correct."
        )
    if storage == "ufs" and not provision:
        warnings.append(
            "UFS target with no --provision-from: the recipe skips re-provisioning "
            "(SkipStorageInit=1) and relies on the existing UFS layout. That is right "
            "for restoring a previously-working unit, but cannot re-create a wiped one."
        )
    if target.gpt is None:
        warnings.append("no target gpt.bin: the GPT flash step will fail. Supply --target-gpt.")

    cpu = donor.cpu_name or "SM_DIVAR"
    recs = [
        si.Record("index.xml", _index_xml(cpu, storage)),
        si.Record("pkg.xml", _pkg_xml()),
        si.Record("default.xml", _default_xml(target, slot, storage, provision)),
        si.Record("programmer.elf", donor.programmer),
    ]
    for label in BOOT_ORDER:
        fn = target.flash_map.get(label)
        if fn and fn in target.parts:
            recs.append(si.Record(fn, target.parts[fn]))
    if target.gpt is not None:
        recs.append(si.Record("gpt.bin", target.gpt))

    blob = si.build(si.with_trailer(recs))

    aux: dict[str, bytes] = dict(donor.qboot)
    aux.setdefault("blank-flash.bat", BLANK_FLASH_BAT.encode())
    aux.setdefault("blank-flash.sh", BLANK_FLASH_SH.encode())

    return ForgeResult(singleimage=blob, aux=aux, warnings=warnings)
