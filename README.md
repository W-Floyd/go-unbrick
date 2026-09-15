# blankflash-forge

Build a Qualcomm/Motorola **blankflash** for a device that has none, by borrowing
the one non-reproducible piece from a **sibling in the same SoC family**.

A blankflash revives a hard-bricked phone stuck in EDL (Qualcomm 9008) by pushing
a `singleimage.bin` with `qboot`. That singleimage needs a Firehose
`programmer.elf` that is **signed against the SoC's secure-boot root and the OEM
key**. You cannot pull that loader off your own device (it is delivered over
Sahara, never stored on a partition) and it is signed **per SoC + OEM, not per
device** — so any sibling on the same SoC and OEM key carries a loader that will
authenticate on yours. Everything else in the singleimage — the boot-chain
partitions and the GPT — is model-specific and comes from **your own stock
firmware**.

This tool does exactly that split: ingest a donor blankflash, harvest the target
from its stock image, and forge a target `singleimage.bin`.

```
donor blankflash  ──ingest──►  programmer.elf (+ qboot)      ┐
target stock       ──harvest─►  boot partitions + gpt.bin    ├─forge─►  singleimage.bin + qboot
                                                              ┘
```

## Worked example: Moto G Play 2024 (fogona, XT2413, SM6225/khaje)

fogona has no public blankflash. Its siblings do: **devon** (Moto G32), **hawao**
(G42), **rhode** (G52) — all SM6225, all Motorola-signed, all share
`cpu.name:SM_DIVAR`.

```sh
# one shot: donor loader + target's own images -> a fogona blankflash
bfforge forge \
  --donor        blankflash_devon_*.zip \
  --target-parts ~/…/postmarketos-fogona/out/dump   \  # raw xbl_a.img, abl_a.img, …
  --target-gpt   ./gpt.bin                           \  # from the fogona stock zip
  -o out/fogona-blankflash
```

`--target-parts` (raw dumps off the live unit) is the most faithful source for a
specific handset; `--target-bootloader path/to/bootloader.img` (from the stock
package) works too.

## Build

Single static binary, no runtime. Go 1.23+:

```sh
go build -o bfforge .           # this platform
GOOS=windows GOARCH=amd64 go build -o bfforge.exe .   # cross-compile
go test ./...                   # unit + parity tests
```

## Commands

| | |
|---|---|
| `bfforge unpack <container> -o dir` | explode any `SINGLE_N_LONELY` image (`singleimage.bin`, `bootloader.img`, UFS `gpt.bin`) |
| `bfforge pack <dir> -o <container>` | rebuild one from an unpacked dir |
| `bfforge ingest <donor> -o dir` | lift `programmer.elf` + `qboot` from a donor (zip/dir/`singleimage.bin`) |
| `bfforge harvest --target-… -o dir` | extract the target's boot partitions + gpt |
| `bfforge forge --donor … --target-… -o dir` | assemble the target blankflash (one-shot, no library) |
| `bfforge inspect <elf\|blankflash\|container>` | dump the secboot identity (root · OEM_ID · HW_ID · SW_ID) of signed images |
| `bfforge catalog list` | vendors · SoCs · devices, with loader/stock status |
| `bfforge catalog family <codename>` | show a device's family and its candidate donor siblings |
| `bfforge catalog stub [-o file]` | generate catalog SoC/device stubs from the loader library |
| `bfforge library add-loader <blankflash>` | ingest a blankflash, detect its family, store the signed loader |
| `bfforge library add-stock <codename> --target-…` | harvest a catalog device's stock and store it |
| `bfforge library list` | loaders (by family) and stock (by device) on hand |
| `bfforge derive <codename> -o dir` | extrapolate a blankflash from a stored family loader + stock |

## What the forge writes

`singleimage.bin` = generated `index/pkg/default.xml` recipe · donor
`programmer.elf` · the target's boot partitions · the target's `gpt.bin` · end
sentinel — plus the donor's `qboot` and `blank-flash.{bat,sh}`.

The recipe is a **minimal restore**: configure storage, flash GPT, flash the boot
chain — no storage re-provisioning. The donor's `<ufs>` LUN-provisioning block is
device- and storage-specific and can deepen a brick, so it is opt-in via
`--provision-from <xml>`. Restoring a previously-working unit does not need it.

## Catalog & library: extrapolating across a family

`forge` is the one-shot primitive. The catalog + library turn it into a growing
map: collect loaders once, then derive a blankflash for any sibling that lacks one.

- **Catalog** (`catalog/*.yaml`, **version-controlled** — this is the mapping, not
  firmware): a flat master list of devices, one entry each carrying `vendor`,
  `cpu_name`, `soc`, `name`, `models`, `storage`. The loader-signing family is
  `(vendor, cpu_name)`: every device sharing that pair shares a loader. `soc` is a
  cosmetic marketing name (may be blank); `models` is an array (a device ships
  several model numbers); `storage` is **advisory only** — real storage is inferred
  from the actual GPT/recipe at harvest time. `bfforge catalog stub` appends flat
  stubs for library families not yet listed.
- **Library** (`library/`, **gitignored** — never commit firmware): signed loaders
  indexed by family, and harvested stock indexed by device. The folder skeleton
  is kept via `.gitkeep`; everything else inside is ignored.
  - `loaders/<vendor>/<cpu_name>/<build>/` — one dir per distinct loader build
    (deduped by SHA256). A family can hold several: the signed loader is *not* one
    fixed blob per SoC — each device build ships its own. `derive` uses the newest
    by default, or `--loader <build>` to pin one (matters against anti-rollback).
  - `stock/<vendor>/<codename>/` — a device's own boot chain + GPT.
  - `donors/` — a convenient stash for the raw blankflash zips you ingest.

```sh
# collect a loader once, from any donor blankflash — its family is auto-detected
bfforge library add-loader blankflash_devon_*.zip     # -> family motorola/SM_DIVAR

# stash a target's own stock (its boot chain + gpt)
bfforge library add-stock fogona --target-parts ./dump --target-gpt ./gpt.bin

# derive fogona's blankflash from the family loader + fogona's own stock
bfforge derive fogona -o out/fogona-blankflash
```

`derive` is limited to devices defined in the catalog. It errors if no family
loader is stored yet (naming the sibling donors to pull one from), and stock can
come from the library or be overridden inline with `--target-…`. A derived
`singleimage.bin` is byte-identical to the equivalent one-shot `forge`.

### Config

`--catalog <dir>` and `--library <dir>` are global. They resolve through flags →
environment (`BFFORGE_CATALOG`, `BFFORGE_LIBRARY`) → an optional `.bfforge.yaml`
in the working dir or `$HOME`, so a fixed library location can live in the
environment instead of every command line:

```sh
export BFFORGE_LIBRARY=~/blankflash-library
bfforge derive fogona -o out/fogona
```

## Cross-model boot-chain donation (`--strip-model`)

By default `forge`/`derive` restore a unit from its **own** stock, copying its boot
partitions verbatim. To instead donate a boot chain from a **sibling model**, an
extended-v3 QCDT device-tree tags each entry with a 32-byte `model` string, and the
bootloader rejects a table whose model ≠ the handset. `--strip-model` removes that
field (72→40 B per entry, zero-filled so every DTB offset stays put) and clears the
`extended` flag, making device-tree matching model-agnostic. It auto-detects and
patches any QCDT part (LZ4-framed or raw); non-QCDT parts pass through untouched.
Opt-in — the default restore path never alters a partition.

## Loader identity & anti-rollback

The signed loader is an aarch64 ELF carrying a Qualcomm hash-table segment: a SHA
table, an RSA-2048 signature, and an X.509 chain (leaf attestation → attestation
CA → root). The leaf cert's OU fields are exactly what the target's PBL enforces:
`OEM_ID`, `HW_ID` (JTAG/SoC ‹‹32 | OEM ‹‹16 | MODEL), and `SW_ID` (a per-image
anti-rollback counter). `bfforge inspect` reads them from any signed image —
including the target's own stock partitions.

`derive` uses this to sanity-check the pairing before forging: it reads the
target's identity from its stock `xbl`/`abl` and compares it to the loader's.

- **`OEM_ID` mismatch is fatal** — a different OEM key will never authenticate.
- **`HW_ID`/root divergence is advisory** — the loader stage's acceptance is
  coarser than a full match (observed: a loader signed under one Motorola root and
  JTAG_ID runs on a sibling fused for another). The true mask is fused per SoC and
  provable only on device.

**SW_ID / anti-rollback — why `derive` picks the *lowest*.** Secboot rejects a
loader whose `SW_ID` is below the target's fused floor. A rejected loader is
harmless and reversible (it just stalls at Sahara). An *over-high* `SW_ID` can be
permanent: if the loader stage commits the anti-rollback fuse, it raises the floor
and locks out every lower version forever. Because rejection costs nothing and
over-shoot can brick, `derive` defaults to the **lowest** stored `SW_ID` and prints
the escalation ladder; step up only if the current one is refused:

```sh
bfforge derive fogona -o out/fogona           # lowest SW_ID
bfforge derive fogona --loader rhode_… -o out  # escalate if that stalled at Sahara
```

The target's own boot chain and the Firehose programmer are *separate* fuse rows,
so the target's stock `SW_ID` does not reveal the programmer floor — the ladder is
how you discover it safely.

## Vendors

The core is vendor-agnostic; per-format packaging lives behind a driver
(`internal/vendor`), selected by catalog vendor id or detected `OEM_ID`. Drivers
carry two orthogonal tags: **platform** (the SoC recovery mechanism —
`qualcomm` EDL/Firehose vs `mediatek` BROM/SP-Flash-Tool) and **vendor/OEM** (the
signing key + packaging). One OEM can span platforms (Motorola ships both).

| layer | scope |
|---|---|
| secboot identity, catalog/library, family matching | **vendor-agnostic** — one implementation |
| donor ingest · stock harvest · package assembly | **per-driver (platform × OEM)** |

- **Motorola** (qualcomm) — full support: `SINGLE_N_LONELY` singleimage + `qboot` + `blank-flash`.
- **MediaTek** (mediatek) — **detection + chip derivation.** Recognizes SP Flash
  Tool packages and derives the SoC from the scatter file — `bfforge inspect
  <mtk.zip>` reports `chip` (e.g. MT6765, the MediaTek analog of Qualcomm's
  `cpu.name`), `project`, `storage`, and partition count, across both scatter
  dialects (flat and storage_type-nested). Ingest/harvest/assemble remain stubs
  (a wholly different BROM/DA transport, no Qualcomm secboot).
- **Samsung** (Qualcomm SoCs) — **identity & detection only.** `inspect` reads its
  signed images (same Qualcomm cert core; `OEM_ID=0020`, root `Samsung Root CA
  cert`), and the driver recognizes `.pit`/Odin/Firehose packages — but ingest,
  harvest, and assembly return "not yet implemented" (Samsung uses a `.pit` table
  with Odin `.tar.md5` or EDL Firehose XML, not `SINGLE_N_LONELY`). It also can't
  be validated end-to-end yet: no Samsung Firehose loader or second unit on hand.

Adding a vendor = implement `vendor.Driver` and register it. Known limitation:
`secboot` parses **64-bit** signed ELFs (xbl, tz, …); some 32-bit partitions
(abl, aop on certain devices) aren't parsed yet.

## The container format (`SINGLE_N_LONELY`)

Reverse-engineered; `bfforge` round-trips real images byte-for-byte.

```
0x000  16B    "SINGLE_N_LONELY\0", rest of a 0x100 block zero
per file:
  +0x000 0x100  header: name (NUL-terminated) @0, u64-LE size @0xf8
  +0x100 size   content, zero-padded up to the next 0x1000 boundary
end:  a record named "LONELY_N_SINGLE", size 0
```

## Caveats — read before flashing

- **Signature is only provable on the device.** Same SoC + OEM key *should*
  authenticate; anti-rollback or a fused SoC revision can still reject it. If the
  loader is refused, `qboot` stalls at Sahara — that is a rejection, not a hang.
- **Storage type must match.** A dual-storage board (fogona ships both eMMC and
  UFS) means the recipe's `MemoryName` and the GPT must match the unit in hand.
  The forge infers storage from the target and warns on a donor/target mismatch.
- **Use the target's own GPT and partitions — never the donor's.** Flashing a
  sibling's boot chain will brick harder.
- EDL is a one-way street without a working loader; do not enter it to "test."
- For lawful repair of a device you own. Ships no firmware — you supply the donor
  blankflash and your own stock images.
