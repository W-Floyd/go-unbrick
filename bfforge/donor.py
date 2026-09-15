"""Ingest a donor blankflash and lift the reusable, signed pieces out of it.

A blankflash is a directory (or zip) holding ``singleimage.bin`` plus the ``qboot``
flasher. The signed ``programmer.elf`` (the Firehose loader) lives inside the
singleimage and is authenticated by the SoC's secure-boot chain against the OEM
key -- so it is reusable across every device that shares that SoC + OEM key, which
is the whole premise of this tool.
"""

from __future__ import annotations

import re
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

from . import singleimage as si

QBOOT_NAMES = ("qboot", "qboot.exe", "qboot.dll", "blank-flash.bat", "blank-flash.sh")


@dataclass
class Donor:
    programmer: bytes  # the signed Firehose loader
    recipes: dict[str, bytes]  # index.xml / pkg.xml / default.xml (donor's own)
    qboot: dict[str, bytes] = field(default_factory=dict)  # flasher binaries, by name
    cpu_name: str | None = None  # qboot cpu.name from index.xml
    storage: str | None = None  # storage.type from index.xml (UFS / eMMC)
    source: str = ""


def _read_dir_or_zip(path: Path) -> dict[str, bytes]:
    """Flatten a blankflash directory or zip into {basename: bytes}."""
    files: dict[str, bytes] = {}
    if path.is_dir():
        for f in path.rglob("*"):
            if f.is_file():
                files[f.name] = f.read_bytes()
    elif zipfile.is_zipfile(path):
        with zipfile.ZipFile(path) as z:
            for n in z.namelist():
                if not n.endswith("/"):
                    files[Path(n).name] = z.read(n)
    elif path.suffix == ".bin" or si.is_container(path.read_bytes()[:16]):
        files[path.name] = path.read_bytes()
    else:
        raise ValueError(f"donor is not a dir, zip, or singleimage: {path}")
    return files


def _meta_from_index(index_xml: bytes) -> tuple[str | None, str | None]:
    txt = index_xml.decode("utf-8", "replace")
    cpu = re.search(r"cpu\.name:([^\s\"]+)", txt)
    store = re.search(r'storage\.type="([^"]+)"', txt)
    return (cpu.group(1) if cpu else None, store.group(1) if store else None)


def ingest(path: str | Path) -> Donor:
    path = Path(path)
    files = _read_dir_or_zip(path)

    singles = [n for n, b in files.items() if si.is_container(b) and n.endswith(".bin")]
    if not singles:
        singles = [n for n, b in files.items() if si.is_container(b)]
    if not singles:
        raise ValueError("no SINGLE_N_LONELY singleimage found in donor")
    recs = si.index(si.parse(files[singles[0]]))

    prog = next((recs[n] for n in recs if n == "programmer.elf"), None)
    if prog is None:
        prog = next((v for n, v in recs.items() if n.endswith(".elf") and b"<data>" in v[:200000]), None)
    if prog is None:
        raise ValueError("donor singleimage has no programmer.elf")

    recipes = {n: recs[n] for n in ("index.xml", "pkg.xml", "default.xml") if n in recs}
    cpu, storage = _meta_from_index(recipes.get("index.xml", b""))
    qboot = {n: files[n] for n in QBOOT_NAMES if n in files}

    return Donor(
        programmer=prog,
        recipes=recipes,
        qboot=qboot,
        cpu_name=cpu,
        storage=storage,
        source=str(path),
    )
