# TODO

## QCDT model-field stripping (cross-model derivation) — DONE

Implemented in `internal/qcdt` (`StripModel`) and wired into `forge`/`derive` as the
opt-in `--strip-model` flag; the helper `stripModels` patches any QCDT part in the
harvested target. LZ4-framed input is decompressed first; an extended-v3 QCDT has
the 32-byte `model` stripped from every entry (72→40 B, zero-filled so DTB offsets
stay valid) and `extended` cleared; non-QCDT / non-extended parts pass through.
Unit-tested (raw + LZ4 + no-op) and smoke-tested end-to-end through `forge`.

Not yet exercised against a **real** sibling `dt.img`/`bootloader.img` — the parts
harvested from current Motorola blankflashes don't carry a separate QCDT, so this
awaits an older-generation donor (e.g. ginna/MSM8953-class) to validate on real
hardware. Also unresolved: whether a target expecting an LZ4-*compressed* dt
partition needs the output re-compressed (the reference tool emits decompressed).

## Container codec: padding assumption

`singleimage.go` hardcodes inter-record padding as round-up to `0x1000`. Two
lineages of prior art corroborate the format, though only one asserts the 4096
padding: HemanthJabalpuri's `star.sh` (and adithya2306's line-for-line Python
port `unpack-moto-img.py`) pad to 4096; playday3008's ImHex template is
alignment-agnostic (skip zeros until the next non-zero byte — compatible but not
independent confirmation of 4096). Round-trip tests prove 0x1000 for the current
corpus. No change needed; revisit only if a non-conforming donor surfaces.

## Document how to obtain `--target-parts`

AndroidDumps `Firmware_extractor/extractor.sh` is the canonical upstream tool that
produces the raw per-partition dumps `harvest --target-parts` / `FromDumps`
consume. Recommend it in the README, with two caveats:
- Its hardcoded `$PARTITIONS` list omits the whole Qualcomm boot chain (`xbl`,
  `abl`, `xbl_config`, `qupfw`, `rpm`, `hyp`, `devcfg`, `keymaster`, `storsec`,
  `prov`, `uefisecapp`; only `tz` overlaps). For **QFIL/rawprogram** inputs it
  iterates that list and will NOT extract them; for **payload.bin** inputs it
  extracts whatever the payload contains (usually including them on A/B devices).
  So it is a reliable source only when the boot-chain partitions are actually in
  the package.
- It never unpacks Motorola `bootloader.img` (SINGLE_N_LONELY); it delegates to
  `star` only for `radio.img` -> NON-HLOS/fsg. The repo's `FromBootloaderImg`
  covers the `bootloader.img` path that extractor.sh does not.

## Source

playday3008 gist `c26833299fe8373a4190ec9360687a77`:
- `moto-qcdt-patch.py`   — LZ4 decompress + model-field stripper
- `moto_dt.hexpat`       — QCDT device-tree table layout (ImHex)
- `moto_bootloader.hexpat` — SINGLE_N_LONELY container layout (ImHex); independent
  confirmation of the codec in `internal/bfforge/singleimage.go`

<https://gist.github.com/playday3008/c26833299fe8373a4190ec9360687a77>
