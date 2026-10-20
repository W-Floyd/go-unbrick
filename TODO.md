# TODO

## Samsung Odin AP — members after super

A deflated `AP_*.tar.md5` in a samfw zip (`tgzseek.OpenDeflate`) lists
`boot`, `dtbo`, `vendor_boot`, `recovery`, `super.img.lz4` by chaining
landings from the head; super (4.7 GiB lz4) cannot be predicted from a 1 MiB
sample, so its sweep exhausts the budget and what follows is not located. The
tail cannot anchor either: the last member decodes to >150 MB of
compressible data with no header in the last 64 MiB of stream. Test package:
SM-M145F M145FXXSDDZH1 (samfw / s01.ooo link). vbmeta_system and anything
else after super are missing until this is solved.

## Samsung — flag a package that is not the latest

`GET https://fota-cloud-dn.ospserver.net/firmware/<CSC>/<model>/version.xml`
(any non-curl User-Agent; curl's default gets 403) lists the latest build
(`PDA/CSC/CP`, e.g. `M145FXXSDDZH1/M145FODMDDZH1/M145FXXSDDZH1` for
SM-M145F/INS) and earlier upgrade builds with sizes. Recon has the model
(`SKU`) and build (`SoftwareVersion`); the CSC is in the Odin CSC member's
name and `meta-data`. `.enc4` downloads are AES-ECB per block (range reads
decrypt in place) but the key needs the signed server exchange — out of scope.

## Remote .tgz — locate the members between super and the tail

`internal/tgzseek` lists a remote `.tgz` exactly at both ends and searches the
middle under a fetch budget (`tgzseek.Budget`); recon marks the listing partial
when the found members' spans do not close the gap to the ISIZE-anchored end.
On the tapas test URL
(<https://bn.d.miui.com/OS2.0.209.0.VMTMIXM/tapas_global_images_OS2.0.209.0.VMTMIXM_20260909.0000.00_15.0_global_2936b5ae03.tgz>)
a cold recon fetches 57 MiB (0.84%) and finds the head, `super.img`, and the
tail cluster `patch5.xml`…`flash_gen_crc_list.py` (incl. `vbmeta_system`,
`tz`, `dtbo`); 2.34 GB of members are not located, `abl`/`vbmeta` among them.
Their facts are reachable meanwhile through `recon --with <the release's OTA>`,
whose name `vendor.Companions` suggests (minus Xiaomi's content hash).

Why (measured): the ISIZE total is 8.85 GB, so ~2.35 GB follows super, in
large members; a ≥160 MB one sits right before `patch5.xml`. No landing in
6.3–7.0 GB compressed (10 MB spacing) hit a header. Super's compressed end is
unknown: integrating sampled compressibility undershoots by ~5% (±300 MB), and
nothing in the stream maps compressed to tar offsets without a contiguous
decode. A landing only finds a header within `LandWalk` after it.

Leads, none verified:
- Predict the member after a found one from its size when it is mostly stored
  blocks (ratio ≈ 1 + 5/16395, exact to KiB); `target` already queues that
  upper bound, but nothing past super has been found to chain from.
- pigz block ends fall at every 128 KiB of output, which gives a landing's tar
  offset mod 128 KiB: a cheap check that a jump landed on the expected header.

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

## Telechips eMMC boot-hardware-partition content is unidentified

`mmcblk0boot0`/`boot1` (Telechips' eMMC hardware boot area, not a named GPT
partition — `internal/transport`'s `identityPartitions` has no path to read
these at all yet) do **not** hold the `TCSBLBS`-tagged `lk.rom` the OTA
package ships (confirmed live on a Mobis G5W unit: full 31.5 MB `boot0` dump
has no `TCSBLBS` anywhere). Instead, two `ANDROID@`-tagged hits, each
followed by `KEY PACKAGES\0` and a small offset table — a different,
smaller structure than the OTA's LK image, unidentified. Content past
~0x79000 is empty/padding. `boot1` (the eMMC mirror) not checked yet.

Open: what this structure actually is (a BL1/SPL stage, a certificate/key
table referenced by `lk.rom`'s own "Key Package to secure image" strings,
or something else), where the real flashed LK actually lives if not here,
and how to read `mmcblk0boot0/1` through go-unbrick at all (they're raw
disks, not `by-name` GPT entries — a different code path than
`IdentityPartitions`).

**Deferred (bigger scope / off the EDL-blankflash mission):**
- **Smart fastboot flash** (`flash --smart`): intersect a stock package's parts
  with the live table to skip missing partitions. The `safeguard` + `PartitionFacts`
  pieces exist, but a stock fastboot flasher is a sizable feature orthogonal to EDL
  recovery.
- **`flashfile.xml` / `servicefile.xml` parser**: Motorola stock manifest → ordered
  flash steps. Useful for ingest, but the stock harvester already handles packages.

## pkg/analysis — embedding, from a library user (3 GiB nudl packages)

In payoff order; `.ver` sub-directories and same-inode are done.

- Hash cache key: device+inode, path as fallback, so hardlinked copies share an
  entry. A real setter (`SetHashCache(path)` or a `Config` field) in place of
  `UNBRICK_HASH_CACHE` and the package global.
- Heads of settled files: with a trusted claim, or the same inode, defer the
  head read (type sniff) until the entry's detail is opened. Matters on a spinning
  array with thousands of files.
- Process-wide state (`apply`, `diffQuiet`, `diffTrust`, prefetch budget,
  `dprog`) into `Run`, so runs can be concurrent.
- Lifecycle: `StartContext(ctx, cfg)`, `Run.Close()`. `web.Handler` keeps 4
  pairs per run (256 MiB cap each): needs a close and a budget option.
- Caps for untrusted callers: byte budget or deadline per run; lower default
  `web` `MaxLimit`.
- Paths in `Run.Err()` and `/api/state` status are absolute: a display root or
  redaction option.
- Weight: `pkg/analysis` pulls in sftp/ssh and every container format (~20 MB)
  even for local dirs; build tag or interface. Needs a tagged release so
  embedders can drop their `replace`.
