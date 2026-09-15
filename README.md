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

## Commands

| | |
|---|---|
| `bfforge unpack <container> -o dir` | explode any `SINGLE_N_LONELY` image (`singleimage.bin`, `bootloader.img`, UFS `gpt.bin`) |
| `bfforge pack <dir> -o <container>` | rebuild one from an unpacked dir |
| `bfforge ingest <donor> -o dir` | lift `programmer.elf` + `qboot` from a donor (zip/dir/`singleimage.bin`) |
| `bfforge harvest --target-… -o dir` | extract the target's boot partitions + gpt |
| `bfforge forge --donor … --target-… -o dir` | assemble the target blankflash |

## What the forge writes

`singleimage.bin` = generated `index/pkg/default.xml` recipe · donor
`programmer.elf` · the target's boot partitions · the target's `gpt.bin` · end
sentinel — plus the donor's `qboot` and `blank-flash.{bat,sh}`.

The recipe is a **minimal restore**: configure storage, flash GPT, flash the boot
chain — no storage re-provisioning. The donor's `<ufs>` LUN-provisioning block is
device- and storage-specific and can deepen a brick, so it is opt-in via
`--provision-from <xml>`. Restoring a previously-working unit does not need it.

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
