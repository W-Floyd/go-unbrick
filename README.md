# go-unbrick

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
unbrick forge \
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
go build -o unbrick .           # this platform
GOOS=windows GOARCH=amd64 go build -o unbrick.exe .   # cross-compile
go test ./...                   # unit + parity tests
```

## Commands

| | |
|---|---|
| `unbrick unpack <container> -o dir` | explode any `SINGLE_N_LONELY` image (`singleimage.bin`, `bootloader.img`, UFS `gpt.bin`) |
| `unbrick pack <dir> -o <container>` | rebuild one from an unpacked dir |
| `unbrick ingest <donor> -o dir` | lift `programmer.elf` + `qboot` from a donor (zip/dir/`singleimage.bin`) |
| `unbrick harvest --target-… -o dir` | extract the target's boot partitions + gpt |
| `unbrick forge --donor … --target-… -o dir` | assemble the target blankflash (one-shot, no library) |
| `unbrick inspect <elf\|blankflash\|container>` | dump the secboot identity (root · OEM_ID · HW_ID · SW_ID) of signed images |
| `unbrick catalog list` | vendors · SoCs · devices, with loader/stock status |
| `unbrick catalog family <codename>` | show a device's family and its candidate donor siblings |
| `unbrick catalog stub [-o file]` | generate catalog SoC/device stubs from the loader library |
| `unbrick library add-loader <blankflash>` | ingest a blankflash, detect its family, store the signed loader |
| `unbrick library add-stock <codename> --target-…` | harvest a catalog device's stock and store it |
| `unbrick library list` | loaders (by family) and stock (by device) on hand |
| `unbrick library harvest [--import]` | gather loaders from community repos, archives, indexes and sites into `harvested_loaders/` |
| `unbrick library import-loaders [dir]` | file harvested loaders into the library (rejects boot stages, containers, digests, patched builds) |
| `unbrick library prune [--write]` | apply the same admission check to loaders already stored |
| `unbrick library reindex [--write]` | re-derive stored loaders' SW_ID / OEM / JTAG from their programmer |
| `unbrick derive <codename> -o dir` | extrapolate a blankflash from a stored family loader + stock |
| `unbrick fastboot recon [--raw] [--redact]` | device recon: getvar, slot health, `oem` probes (incl. `cid_prov_req` decode), catalog/library match |
| `unbrick ssh recon <user@host> [--read-partitions]` | recon a phone booted into Linux (postmarketOS, Mobian, …) over ssh |
| `unbrick adb recon [--read-partitions]` | recon a phone booted into Android over adb |
| `unbrick adb debloat [--apply]` | list, and optionally remove, preloaded carrier/OEM packages (per-user, reversible, no root) |
| `unbrick adb provision <recipe> [--apply]` | set a device up from a recipe: install, grant, configure headlessly, verify |
| `unbrick recon <file>` | identify any file (stock zip, image, container, config) and report what it is |
| `unbrick fastboot edl` | drop a fastboot device into EDL (9008) |
| `unbrick edl setcid <bundle> <value>` | write a software channel to the `cid` partition (verified by read-back; see *CID provisioning*) |
| `unbrick edl readcid <bundle>` | read the `cid` partition and print its channel |

## Recon over a booted device (ssh / adb)

A booted phone answers what no bootloader will, and hands over what a locked
bootloader never would. `unbrick ssh recon user@host` collects from a Linux
install (which distribution and kernel, its device package's idea of the
device, the SoC as sysfs reports it, the whole partition table by name);
`unbrick adb recon` does the same from an Android userspace (build fingerprint,
patch level, the property system). Both go through the same fact graph as a
firmware package, so a device fact and a package fact cross-check each other:

```bash
# what is this phone, and does the catalog/library know it?
unbrick ssh recon user@172.16.42.1

# with root: read the identity and boot-chain partitions and derive from their
# content — CID, HAB signing identity, AVB key and rollback index, cert chains.
# This is otherwise an EDL-only capability.
unbrick ssh recon user@172.16.42.1 --read-partitions

# compare the running device against the firmware it should have
unbrick adb recon --against ~/firmware/fogona_U1TF34.100-35-14.zip
```

ssh uses Go's own client: the agent and `~/.ssh` keys first, a password only if
no key works (`UNBRICK_SSH_PASSWORD` for unattended runs), host keys checked
against `known_hosts` (`--host-keys=accept-new` to record a new one — a
reflashed phone presents a new key). `--ssh` drives the host `ssh` binary
instead, for a `~/.ssh/config` alias or a ProxyJump. adb talks the adb server
protocol directly, starting a server with the `adb` binary if none is running.

Reading partitions needs root on the device: root login, a passwordless
`doas`/`sudo`, a `sudo` that takes a password (it is fed over the encrypted
channel), or `su` on a rooted Android. Which partitions are worth reading, and
how a distribution names its device, are both data — see
[docs/design/transports.md](docs/design/transports.md) and
`catalog/distros.yaml`.

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
  `cpu_name`, `soc`, `name`, `models`, `storage`, and optional `jtag_id`. A loader
  authenticates by the fused **JTAG_ID** the PBL checks, not by `cpu_name` (a lossy
  qboot packaging label: one `cpu_name` spans several JTAG_IDs and vice-versa). A
  device that records its `jtag_id`(s) resolves loaders exactly; one that omits it
  falls back to the `cpu_name` bridge (a loader carrying both links the two). `soc`
  is a cosmetic marketing name (may be blank); `models` is an array (a device ships
  several model numbers); `storage` is **advisory only** — real storage is inferred
  from the actual GPT/recipe at harvest time. `unbrick catalog stub` appends flat
  stubs for library families not yet listed (with `jtag_id` from the loader cert),
  and `unbrick catalog backfill` fills `jtag_id` on existing devices from library
  loaders whose source names them — never from the lossy cpu_name bridge. Read a
  device's own `jtag_id` from any signed image with `unbrick inspect`.
- **Library** (`library/`, **gitignored** — never commit firmware): signed loaders
  indexed by family, and harvested stock indexed by device. The folder skeleton
  is kept via `.gitkeep`; everything else inside is ignored.
  - `loaders/<vendor>/<jtag_id>/<build>/` — one dir per distinct loader build
    (deduped by SHA256), keyed on the JTAG_ID the loader authenticates against. A
    family can hold several: the signed loader is *not* one fixed blob per SoC —
    each device build ships its own. `derive` uses the lowest SW_ID by default, or
    `--loader <build>` to pin one (matters against anti-rollback).
  - `stock/<vendor>/<codename>/` — a device's own boot chain + GPT.
  - `donors/` — a convenient stash for the raw blankflash zips you ingest.

```sh
# collect a loader once, from any donor blankflash — its family is auto-detected
unbrick library add-loader blankflash_devon_*.zip     # -> family motorola/SM_DIVAR

# stash a target's own stock (its boot chain + gpt)
unbrick library add-stock fogona --target-parts ./dump --target-gpt ./gpt.bin

# derive fogona's blankflash from the family loader + fogona's own stock
unbrick derive fogona -o out/fogona-blankflash
```

`derive` is limited to devices defined in the catalog. It errors if no family
loader is stored yet (naming the sibling donors to pull one from), and stock can
come from the library or be overridden inline with `--target-…`. A derived
`singleimage.bin` is byte-identical to the equivalent one-shot `forge`.

### Config

`--catalog <dir>` and `--library <dir>` are global. They resolve through flags →
environment (`UNBRICK_CATALOG`, `UNBRICK_LIBRARY`) → an optional `.unbrick.yaml`
in the working dir or `$HOME`, so a fixed library location can live in the
environment instead of every command line:

```sh
export UNBRICK_LIBRARY=~/unbrick-library
unbrick derive fogona -o out/fogona
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
anti-rollback counter). `unbrick inspect` reads them from any signed image —
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
unbrick derive fogona -o out/fogona           # lowest SW_ID
unbrick derive fogona --loader rhode_… -o out  # escalate if that stalled at Sahara
```

The target's own boot chain and the Firehose programmer are *separate* fuse rows,
so the target's stock `SW_ID` does not reveal the programmer floor — the ladder is
how you discover it safely.

You also cannot **patch** a signed loader to lift a restriction: the BootROM
re-hashes and re-verifies the programmer over Sahara *before running it*, against
the OEM root-key hash fused in QFPROM. Any edit breaks the signature and the mask
ROM refuses to execute it. Getting past that needs un-fused (engineering) silicon,
a per-SoC Sahara/Firehose exploit, or the OEM key — not a loader edit.

## Debloating a carrier device (`adb debloat`)

A locked, unrooted, carrier-subsidy phone can still lose its preloads, because
`pm uninstall --user 0` is a *per-user* state change: no partition is written,
dm-verity and the bootloader lock are untouched, the APK stays in the image, and
`--restore` (or a factory reset) puts it back. That is the whole basis of this
command, and the reason it will never grow a flashing path.

```bash
unbrick adb debloat                  # print the plan, change nothing
unbrick adb debloat --list           # every installed package, classified
unbrick adb debloat --unknown        # what the catalog does not name yet
unbrick adb debloat --apply          # everything safe (typed confirmation)
unbrick adb debloat --max-risk caution --apply        # also the feature-costing ones
unbrick adb debloat --category carrier --max-risk invasive --apply
unbrick adb debloat --restore debloat-ZLTEST0003.json
```

Selection has two independent axes, because "what a package is for" and "what
removing it costs" are different questions:

**`--category`** — what to consider. **ads** (the sponsored-app installers —
Aura/ironSource, Digital Turbine Ignite, Swish Deals, Motorola's own preload
agents; removing these stops re-delivery), **preload** (third-party apps the
channel shipped), **oem-extra** (the manufacturer's optional software),
**carrier** (this unit's *own* carrier apps, such as TracFone's Device Pulse
diagnostics agent), **carrier-foreign** (another carrier's client on this unit),
**updates** (the OTA machinery).

**`--max-risk`** — how much a removal may cost. **safe** (nothing a stock phone
depends on), **caution** (a named feature goes away — FM radio, face unlock,
Family Space, the Moto app hub), **invasive** (activation, updates or a carrier
feature may be affected).

The default is `--category ads,preload,oem-extra --max-risk safe`: *everything
nothing depends on*, which is what the risk field already claims about a `safe`
entry — so withholding a safe package on account of its category would make the
risk label decorative. Anything that costs a feature is listed with what it
costs and waits to be asked for (`--max-risk caution`). The three categories
left out of the default are the ones where the *category itself* carries a
consequence no risk label captures: `carrier` (this device's own service),
`carrier-foreign` (harmless now, relevant if the SIM ever changes) and `updates`
(every future security patch).

A package the shell may not uninstall — a privileged system package, which
answers `DELETE_FAILED_INTERNAL_ERROR` or "package is non-disable" — is
**disabled instead**, which reaches the same end: it does not run. The record
keeps those separate, and `--restore` re-enables them rather than reinstalling.
A package the image already ships disabled is reported as such and not proposed.

Two properties worth knowing:

- **Telephony, IMS, provisioning, setup and the carrier-unlock client are
  protected in code** (`internal/bloat`), not in the catalog, so editing the
  catalog cannot select them — and `--only <package>` does not override a
  protection either. On a TracFone unit that includes the Verizon APN and
  provisioning packages, since TracFone runs on Verizon: a tidy app drawer is
  not worth the data connection.
- **A package `catalog/bloat.yaml` does not name is never proposed.** The table
  was read off a real device (fogona, XT2413V, TracFone channel, Android 14),
  and most of that unit's 461 packages are still unclassified — they are
  reported by `--unknown`, not guessed at. Where an entry's meaning was not
  obvious from the package name, the label was read off the APK
  (`adb pull` + `apkanalyzer`), which is how `com.motorola.om` turned out to be
  "Moto Unplugged", `com.motorola.spaces` to be "Family Space", and
  `com.tracfone.preload.accountservices` to be TracFone's "Device Pulse"
  diagnostics agent rather than the activation plumbing its name suggests.

Removal is only locally reversible for APKs that live in the image. The
sponsored apps a delivery agent installs during setup sit in `/data`, so the
plan marks them and the record keeps them on a separate list: those come back
from the Play Store, not from `--restore`.

## Provisioning a device (`adb provision`)

The inverse of debloating: putting a device *into* a known state. A recipe in
`catalog/provision.yaml` is a sequence of verbs this tool implements — install,
device_owner, grant, appop, start, settings, disable, enable, verify — with
values filled in by `--var`. A recipe cannot name a shell command to run, by
design: a table that can run anything on a phone is a script with fewer
safeguards, and this one is meant to be read by whoever is about to trust it.

```bash
unbrick adb provision --list
unbrick adb provision freekiosk --var url=https://dash.local --var pin=1234
unbrick adb provision freekiosk --var lock_package=com.example.app --var pin=1234 \
    --apk ~/Downloads/freekiosk-v2.2.20.apk --apply
unbrick adb provision freekiosk-undo --apply       # release the device
```

Shipped recipes:

| recipe | what it does |
|---|---|
| `freekiosk` | [FreeKiosk](https://github.com/RushB-fr/freekiosk) alone: lock to an installed app, or show a URL in its WebView |
| `ha-kiosk` | Home Assistant Companion **plus** FreeKiosk as the enforcement shell around it |
| `freekiosk-undo` | give up device owner and release the device |

`ha-kiosk` is the combination that is usually wanted: the HA app keeps what it is
good at (native dashboard, push notifications, the companion sensors that feed
automations) while FreeKiosk supplies what a normal app cannot — lock-task so the
screen cannot be left, a PIN-gated exit, relaunch after a crash, launch on boot.

```bash
# fetches app-full-release.apk and the FreeKiosk release APK itself
unbrick adb provision ha-kiosk --var pin=1234 --apply

# or stage the downloads first, e.g. before taking the device somewhere offline
unbrick adb provision ha-kiosk --var pin=1234 --fetch-only
unbrick adb provision ha-kiosk --var pin=1234 --no-download --apply

# the minimal HA build, for a device without Play services
unbrick adb provision ha-kiosk --var pin=1234 \
    --asset ha=app-minimal-release.apk \
    --var ha_package=io.homeassistant.companion.android.minimal --apply
```

Its order is deliberate: install both APKs over adb, **then** clear accounts,
**then** set device owner. Installing HA from the Play Store would add a Google
account and block device owner — while the accounts-free requirement applies only
to *setting* it, so once set you can sign in again and take Play updates as
normal. Signing into Home Assistant itself cannot be automated, so that is a
first-class `manual` step: the plan lists it in order and the run pauses on it,
rather than locking the device onto a login screen nobody can escape.

**Clearing accounts over adb.** An account exists because some package serves
its type, and the preflight now names that package: on the observed unit the
only account was `TracFone (com.motorola.contacts.preloaded, owned by
com.motorola.contacts.preloadcontacts)` — a removable preload, not a Google
account. So `--var account_holder=com.motorola.contacts.preloadcontacts` clears
the device-owner precondition with a per-user uninstall, no Settings visit and
no factory reset, and the preflight recognises that the plan resolves its own
precondition instead of refusing to start. A Google account is different: its
owner is Play services, which is not removable, so that one is removed in
Settings or by a reset.

**Updating sideloaded apps.** `--only install` re-runs just the install steps,
which is `pm install -r` — app data and configuration survive, the device owner
is untouched, and lock-task keeps running:

```bash
unbrick adb provision ha-kiosk --var pin=1234 --only install \
    --apk ha=~/Downloads/app-full-release.apk --apply
```

Otherwise: after device owner is set you may add a Google account again and let
Play update HA normally; FreeKiosk is not on Play, so it comes from GitHub
releases (Obtainium tracks those well). On a kiosk, unattended updates are a
mixed blessing — a dashboard that changes at 3am is a dashboard nobody asked to
change — which is the argument for the `--only install` path on your own
schedule.

Recipes and bloat rules are both **vendor-scoped**: an entry may carry
`vendor: motorola`, and on any other OEM's device it is dropped rather than
applied — a rule about a package the maintainer has only seen on a Motorola
cannot vouch for anything on a Samsung, so the honest result there is
"unknown". Rules with no `vendor` are the ones that genuinely are everyone's:
the Android platform, Google's packages, the ad-delivery agents, the games. The
`ha-kiosk` and `freekiosk` recipes are unscoped, because neither app cares who
built the phone; the one OEM-specific thing a run may need (which preload owns
an account) is discovered from the device rather than tabulated per vendor.

Four things the command insists on:

- **The plan first.** A default run prints every command it would send, in
  order, with the irreversible ones marked, and changes nothing. `--apply` runs
  them, stopping at the first failure and writing a record.
- **Preconditions before the irreversible step.** `dpm set-device-owner` refuses
  if any account is configured, and it refuses *after* the APK is installed —
  so the accounts, the existing owner and the API level are checked up front.
  Skip the owner step (`--skip device_owner`, which upstream documents as fine
  for URL kiosk mode) and those checks become notes rather than blockers.
- **A separate confirmation for what cannot be undone.** Device Owner needs a
  factory reset to clear on most builds, so accepting the run and accepting that
  step are two answers, not one.
- **Fetching the APKs, checkably.** The recipe names a source — a GitHub
  project's latest release plus the asset to take, or a direct URL — and the
  plan resolves it to an exact asset, tag, size and URL *before* anything is
  transferred; the download itself waits for `--apply`. Files land in
  `<library>/apks` keyed by release tag, so a second run installs the same bytes
  rather than whatever upstream published since. `sha256:` in a recipe is
  verified and refuses on a mismatch; without it, the run prints the digest of
  what it installed so you can pin it. `gh` is used for GitHub when present (it
  brings your auth and rate limit), `--apk` uses a file you already have,
  `--no-download` refuses the network, and `--fetch-only` stages the downloads
  without touching the device.
- **No secrets on screen.** A value marked secret — a PIN, an API key — is
  masked in the plan and left out of the record, because an intent extra is
  visible on the device's own command line and in logcat while the app starts.

## CID provisioning & the `cid` partition (Motorola)

The `cid` (Customer ID) partition sets the carrier/software channel and gates AP
fastboot flashing; a corrupt/tampered `cid` makes ABL report CarrierID
`0xDEAD`/`0xFFFF` and blocks flashing. `unbrick fastboot recon` reads and
cross-references it — `--raw` prints the full device dumps, `--redact` masks
per-device identifiers for sharing.

**Two on-device formats** (`cid.Version`): version **0** is the 44-byte *unsigned*
template (`00f0 0000 …002c`, a u16 channel at `0x2a`) — the stock/flashfile form
`edl setcid` writes. Version **2** is a *signed* structure seen on
secure-production units (a live fogona): `00f0 0002 …0070` carrying the chip
serial, SoC id, CID, device serial and product name, then an RSA signature and an
embedded X.509 chain (leaf `LEN01MPKI01` → `PKIS SubCA` → the ABL's `PKIS Root`),
~2.4 KB on a real dump (**not** a recomputable hash — it needs Motorola's PKI).

**A CID names a channel less precisely than it looks.** It is the key the
bootloader matches a package against, and two fogona packages declare
`cid_value 0x0032` while disagreeing about everything else:
`XT2413-2_FOGONA_RETUS_…_subsidy-DEFAULT` (manifest: subsidy none, retail) and
`XT2413-2_FOGONA_CC_…_subsidy-CCAWS` (manifest: subsidy LOCKED to T-Mobile/AT&T).
So `catalog/motorola.yaml` names only what every observation of a CID agrees on,
and the subsidy lock stays a per-*package* fact read from the `slcf` the package
carries. A CID label asserting a lock made recon print "subsidy lock CCAWS" over
a retail package that says "Subsidy: none" two lines below.

**Carrier CID vs signing CID, read off a device.** fogona's HAB (signing/base)
CID is `0x0032` on *every* variant — including the packages whose carrier
`cid_value` is `0x0033` — so a `cid` partition read that returns `0x0032` on this
family cannot by itself distinguish "carrier CID 0x0032" from "the base CID of a
unit whose carrier CID is something else". `fastboot getvar cid` is the
authoritative answer for a live device, which is why the partition-derived value
stays `Derived` and loses to a package manifest on a conflict.

**`oem cid_prov_req`** is the after-sales provisioning *request* recon decodes:
the SoC id (in the clear, cross-checked to `JTAG_ID`), the format version, and a
16-byte device digest. The dump is a masked copy of the live `cid` partition
(serial and one field blanked) plus the digest. The digest is device-unique,
stable, and **not derivable** from any visible id (chip/UFS/SoC/serial) — it is
hardware-key-derived (RPMB/HUK) and treated as a per-device secret.

**You cannot raw-write the `cid`** — three independent walls, all rooted in the
QFPROM fuses:
1. the Firehose loader is BootROM-signature-verified before it runs (above);
2. the production `prog_firehose_lite.elf` restricts partition access: it *ACKs* a
   `cid` write and silently discards it — so `edl setcid` reads the partition back
   and fails loudly if the write did not land, rather than trusting the ACK;
3. a valid version-2 `cid` is PKI-signed and bound to the device digest, so only
   Motorola's server (`cid_prov_req` → `cid_prov_data` → `ssm_flash_cid`) can mint
   one; a payload from one device cannot be replayed to another.

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
  Tool packages and derives the SoC from the scatter file — `unbrick inspect
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

Reverse-engineered; `unbrick` round-trips real images byte-for-byte.

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
