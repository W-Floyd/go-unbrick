"""Command line: unpack/pack the container, and ingest -> harvest -> forge."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import donor as donor_mod
from . import forge as forge_mod
from . import singleimage as si
from . import target as target_mod


def _write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


def cmd_unpack(a: argparse.Namespace) -> int:
    recs = si.parse(Path(a.container).read_bytes())
    out = Path(a.out)
    manifest = []
    for r in recs:
        if r.name == si.TRAILER:
            continue
        _write(out / r.name, r.data)
        manifest.append({"name": r.name, "size": len(r.data)})
    _write(out / "manifest.json", json.dumps(manifest, indent=2).encode())
    for m in manifest:
        print(f"  {m['size']:>10}  {m['name']}")
    print(f"{len(manifest)} records -> {out}")
    return 0


def cmd_pack(a: argparse.Namespace) -> int:
    d = Path(a.dir)
    manifest = json.loads((d / "manifest.json").read_text())
    recs = [si.Record(m["name"], (d / m["name"]).read_bytes()) for m in manifest]
    blob = si.build(si.with_trailer(recs))
    _write(Path(a.out), blob)
    print(f"packed {len(recs)} records -> {a.out} ({len(blob)} bytes)")
    return 0


def cmd_ingest(a: argparse.Namespace) -> int:
    d = donor_mod.ingest(a.donor)
    out = Path(a.out)
    _write(out / "programmer.elf", d.programmer)
    for n, b in d.recipes.items():
        _write(out / n, b)
    for n, b in d.qboot.items():
        _write(out / n, b)
    print(f"donor: cpu.name={d.cpu_name} storage={d.storage} "
          f"programmer.elf={len(d.programmer)}B qboot={list(d.qboot)}")
    print(f"-> {out}")
    return 0


def _load_target(a: argparse.Namespace) -> target_mod.Target:
    gpt = Path(a.target_gpt).read_bytes() if a.target_gpt else None
    if a.target_parts:
        return target_mod.from_dumps(a.target_parts, slot=a.slot, gpt=gpt)
    if a.target_bootloader:
        return target_mod.from_bootloader_img(Path(a.target_bootloader).read_bytes(), gpt=gpt)
    raise SystemExit("need --target-bootloader or --target-parts")


def cmd_harvest(a: argparse.Namespace) -> int:
    t = _load_target(a)
    out = Path(a.out)
    for fn, b in t.parts.items():
        _write(out / "parts" / fn, b)
    if t.gpt is not None:
        _write(out / "gpt.bin", t.gpt)
    _write(out / "meta.json", json.dumps(
        {"storage": t.storage, "flash_map": t.flash_map, "source": t.source,
         "parts": {k: len(v) for k, v in t.parts.items()}}, indent=2).encode())
    print(f"target: storage={t.storage} parts={len(t.parts)} gpt={'yes' if t.gpt else 'no'}")
    for label, fn in t.flash_map.items():
        mark = "" if fn in t.parts else "  (MISSING)"
        print(f"  {label:<12} {fn}{mark}")
    print(f"-> {out}")
    return 0


def cmd_forge(a: argparse.Namespace) -> int:
    d = donor_mod.ingest(a.donor)
    t = _load_target(a)
    provision = Path(a.provision_from).read_bytes() if a.provision_from else None
    res = forge_mod.forge(d, t, slot=a.slot, storage=a.storage, provision=provision)

    out = Path(a.out)
    _write(out / "singleimage.bin", res.singleimage)
    for n, b in res.aux.items():
        _write(out / n, b)

    print(f"forged singleimage.bin: {len(res.singleimage)} bytes, "
          f"{len(si.index(si.parse(res.singleimage)))} records")
    print(f"  donor loader: {d.source}  cpu.name={d.cpu_name}")
    print(f"  target: {t.source}  storage={t.storage or a.storage}")
    for w in res.warnings:
        print(f"  ! {w}", file=sys.stderr)
    print(f"-> {out}  (run blank-flash.bat / blank-flash.sh with the device in EDL 9008)")
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="bfforge", description=__doc__)
    sub = p.add_subparsers(dest="cmd", required=True)

    u = sub.add_parser("unpack", help="explode a SINGLE_N_LONELY container")
    u.add_argument("container")
    u.add_argument("-o", "--out", required=True)
    u.set_defaults(func=cmd_unpack)

    k = sub.add_parser("pack", help="rebuild a container from an unpacked dir")
    k.add_argument("dir")
    k.add_argument("-o", "--out", required=True)
    k.set_defaults(func=cmd_pack)

    i = sub.add_parser("ingest", help="lift programmer.elf + qboot from a donor blankflash")
    i.add_argument("donor", help="donor blankflash: zip, dir, or singleimage.bin")
    i.add_argument("-o", "--out", required=True)
    i.set_defaults(func=cmd_ingest)

    def add_target(sp: argparse.ArgumentParser) -> None:
        sp.add_argument("--target-bootloader", help="target stock bootloader.img")
        sp.add_argument("--target-parts", help="dir of raw target dumps (xbl_a.img ...)")
        sp.add_argument("--target-gpt", help="target gpt.bin (from stock package)")
        sp.add_argument("--slot", default="a", choices=["a", "b"])

    h = sub.add_parser("harvest", help="extract target partitions + gpt from stock")
    add_target(h)
    h.add_argument("-o", "--out", required=True)
    h.set_defaults(func=cmd_harvest)

    f = sub.add_parser("forge", help="assemble a target blankflash")
    f.add_argument("--donor", required=True, help="donor blankflash (zip/dir/singleimage.bin)")
    add_target(f)
    f.add_argument("--storage", choices=["emmc", "ufs"], help="override target storage type")
    f.add_argument("--provision-from", help="XML file with a target-specific provisioning block")
    f.add_argument("-o", "--out", required=True)
    f.set_defaults(func=cmd_forge)

    a = p.parse_args(argv)
    return a.func(a)


if __name__ == "__main__":
    raise SystemExit(main())
