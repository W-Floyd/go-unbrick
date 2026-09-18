# TODO

## QCDT model-field stripping — validation pending

`internal/qcdt` (`StripModel`, wired as `--strip-model`) is implemented and
unit/smoke tested, but not yet exercised against a **real** sibling
`dt.img`/`bootloader.img` — current Motorola blankflashes carry no separate QCDT,
so this awaits an older-generation donor (e.g. ginna/MSM8953-class) to validate on
hardware. Also unresolved: whether a target expecting an LZ4-*compressed* dt
partition needs the output re-compressed (the reference tool emits decompressed).

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
  confirmation of the codec in `internal/blankflash/singleimage.go`

<https://gist.github.com/playday3008/c26833299fe8373a4190ec9360687a77>

## CID provisioning — open items

RE'd from two fogona units plus a real `cid` dump; the settled findings live in the
README (*CID provisioning*) and `internal/cid`. Still open:

- Replace `fogona-abl-notes/out/extracted/abl/MotoBootModule.efi` (a bad
  `0x1000`-short extraction) with the device's real 1040384 B build, saved at
  `samples/MotoBootModule_ZLTEST0001_abl_a.efi`.
- Possible **`setcid` guard**: read the current `cid` and refuse/warn on
  `cid.IsSigned` before writing v0. Deferred — the read-back verify already makes
  a non-persisting write fail loudly, and on tested units the write simply bounces
  (no brick), so a hard guard may be unnecessary.

## recon/ Tiny-Fastboot-Script — folded opportunities

Assessed from `recon/ANALYSIS.md` against the current fastboot architecture
(neutral `internal/fastboot` + vendor profile/command seams). Priority order:

**Worth doing (small, neutral, low-risk):**
- **Partition-name platform heuristic.** Classify SoC from partition names when
  `getvar` cpu/product is ambiguous (`fsg`/`xbl`/`tz`→Qualcomm,
  `preloader`/`lk`/`md_udc`→MediaTek, `sboot`/`tzsw`/`ldfw`→Exynos). Names are
  already in `DeviceRecon.PartitionSizes`; a neutral helper in `internal/fastboot`.
  Value: tell a user early when a device is *not* an EDL-blankflash target.
- **GPT / slot-metadata corruption warning.** `slot-count ≥ 2` but empty
  `current-slot` → flag corrupt slot metadata in the recon report. Two lines off
  existing `SlotCount`/`CurrentSlot`.

**Fits the vendor-command seam, but needs a confirm gate (write commands):**
- **Factory-state sanitizer** as a Motorola `FastbootCommander` (`fastboot
  sanitize`): `oem config cmdl ""`, `oem off-mode-charge enable`,
  `oem ramdump disable`, `oem fb_mode_clear`. Real value for a device stuck in
  ramdump/fb_mode, but these mutate state (`cmdl ""` wipes the kernel cmdline), so
  gate per-flag with an explicit confirm, not fire-all.

**Deferred (bigger scope / off the EDL-blankflash mission):**
- **Smart fastboot flash** (`flash --smart`): intersect a stock package's parts
  with the live table to skip missing partitions. The `safeguard` + `PartitionFacts`
  pieces exist, but a stock fastboot flasher is a sizable feature orthogonal to EDL
  recovery.
- **`flashfile.xml` / `servicefile.xml` parser**: Motorola stock manifest → ordered
  flash steps. Useful for ingest, but the stock harvester already handles packages.
