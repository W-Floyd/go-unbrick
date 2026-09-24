# Transports: one recon, many routes

A phone is reachable in several states, and each state is a different
conversation: a bootloader in fastboot mode, a booted Linux distribution over
ssh, a booted Android userspace over adb, a dead device over EDL, a Samsung in
download mode. What can be *asked* differs per route. What is done with the
answers does not.

So a transport's whole obligation is to put what the device said into the Bag as
source facts. Everything after that — the derivations, the cross-checks, the
authority order, the report — belongs to the fact graph (see
[facts-derivation.md](facts-derivation.md)) and is written once.

Status: built. `internal/transport`, adapters for fastboot, ssh, adb, EDL and file,
and one command driver (`runTransportRecon`) that all of them share.

## The seam

```go
type Transport interface {
    Name() string                          // fastboot | ssh | adb | edl | file | odin
    Describe() string                       // "ssh user@fogona (postmarketOS edge)"
    Sources(*facts.Bag) []facts.Finding     // what the device said, as source facts
    Close() error
}
```

Capabilities are opt-in sub-interfaces, the way `vendor.Driver` and
`fastboot.Profile` do it — a route implements only what it can honestly do, and
the command layer asks with a type assertion:

```go
type PartitionLister interface { Partitions() []Partition; Slot() string }
type PartitionReader interface { ReadPartition(Partition) ([]byte, error); ReadCost() int }
```

`Partition` carries a `Handle`: a device node on a booted route, a LUN and
sector range on EDL, nothing where the name is the address. It is opaque to
everyone but the transport that produced it.

The asymmetry is the point. `fastboot` will describe a partition all day and
never hand one over, because the protocol has no read verb; the command layer
can therefore tell the operator *which route would* instead of failing at the
last moment. A recon that wants partition content off a locked device has to
boot it into Linux or Android, or go in over EDL.

## What each route knows

| | fastboot | ssh (Linux) | adb (Android) | file | EDL | Odin |
|---|---|---|---|---|---|---|
| identity facts | `getvar all`, vendor `oem` probes | os-release, distro device definition, sysfs, cmdline | property system, sysfs, cmdline | package manifests, image headers | Sahara fuses, GPT, partition content | `.pit`, partition content |
| lists partitions | ✅ names + sizes | ✅ whole live table | ✅ whole live table | (a GPT dump or package: **next**) | ✅ from GPT | ✅ from `.pit` |
| reads partitions | ❌ no read verb | ✅ with root | ✅ with root | n/a — it *is* the bytes | ✅ on a dead device | ✅ |
| works when the device will not boot | ✅ if the bootloader runs | ❌ | ❌ | ✅ | ✅ | ✅ |
| status | built | built, verified on hardware | built, verified on hardware | built | Sahara verified on hardware; Firehose built | **not implemented** |

EDL (`unbrick edl recon`) speaks in two stages. Sahara, before any programmer
runs, reports the fused chip identity — JTAG id, OEM id, OEM_PK_HASH — as the
`jtag_id`, `oem_id` and `root_key_hash` facts, which a signed image's cert chain
also yields; an image signed for other silicon is then an ordinary same-fact
conflict. The same identity judges every stored loader before one is sent: the
PBL accepts a loader whose root certificate hashes to the fused PK hash
(SHA-384 on SM6225, over roots signed with SHA-256, so the digest is the chip's
choice, not the chain's). Firehose, with `--loader` or `--loader=library`, lists
the GPT and reads partitions. A running programmer ends Sahara until a power
cycle, so a loader-backed recon takes the chip identity from the handshake of
the session that uploads it.

Odin is shaped for, not written. Samsung download mode, as Heimdall speaks it,
is a `.pit` table where Qualcomm has a GPT, and reads partitions on devices with
no other route in.

## A file is a route

`transport.File` is deliberately on that list. A firmware package is not a
device, but the seam is not about connections — it is about putting what a thing
says into the Bag, which is exactly what ingesting a package does.

Naming it a route is what lets one recon hold two. `--against <package>` reads
the firmware a device is supposed to be running as a second source, and the
disagreements — a CID that does not match the package, an anti-rollback index
the device has moved past, a fingerprint from another build — fall out of the
graph's ordinary same-fact comparison. There is no comparison code.

## Shell-reachable routes share nearly everything

ssh and adb both reach a POSIX shell on a booted device, and a booted device
answers the same questions either way: `/proc/cmdline` carries what the
bootloader passed (slot, serial, verified-boot state), `/sys/devices/soc0`
carries what the silicon says it is, `/dev/block/by-name` carries the whole
partition table. Only the identity of the *userspace* differs — os-release and a
distribution's device definition on one side, the property system on the other.

So `internal/transport` holds:

- `CommonShellScript` — one POSIX script (busybox ash on postmarketOS,
  toybox/mksh on Android), collected in a single round trip. Every read is
  guarded, so a device with no device-tree or no by-name directory still yields
  everything else.
- `ShellRecon` + `ParseShell` — the common record and its parsers.
- `ShellProviders(source, key, get, level)` — the derivations any shell route
  contributes (slot, lock state, A/B, SoC via the catalog, the device tree's
  codename), declared once and registered by each route over its own typed
  source key.

Two rules in that script are not style. Both were learned from devices:

- **Never redirect an unreadable file into a filter.** `tr -d '\0' < $f` looks
  harmless; when the redirect fails, the shell leaves `tr` reading the
  *session's* stdin, which over ssh or adb never closes. The collection stops
  dead at the first sysfs file the login cannot read — which on an unrooted
  Android shell is `/sys/devices/soc0/eva`, three sections in. Every read is
  `cat $f 2>/dev/null </dev/null | …` instead, which cannot do that.
- **Ask sysfs for the attributes actually read, not for the directory.**
  `/sys/devices/soc0` holds vendor entries that query a subsystem when read; the
  neutral facts need fourteen names, so the script names them.

What a route cannot see is as much a finding as what it can. An unrooted adb
shell may read neither `/proc/cmdline` nor `/sys/class/block`, so: the
bootloader's parameters are recovered from the `ro.boot.*` properties that
mirror them (the cmdline wins where both answer, being one copy closer to the
bootloader), and a partition size of 0 means "the device would not say" rather
than "empty" — such a partition is still read, bounded by the read cap, and a
read that hits the cap is reported as the fragment it is rather than handed to
the recognizers as an image.

Both shell routes declare their facts **Derived**: everything passed through a
mutable userspace and a kernel command line the installed system may have
replaced, so a bootloader's or a package's version of the same fact wins the
display while the disagreement still surfaces. The exception is the identity of
the install itself (`device_os`, `kernel_release`) — nothing is more
authoritative about what is installed than the system answering.

## Clients

Both booted routes speak their protocol in Go rather than driving a host binary
per command, because a recon asks twenty questions and a process per question is
both slow and, on a password-authenticated device, twenty prompts.

- **ssh** — `golang.org/x/crypto/ssh`: one connection, a session per command.
  Keys first (agent, then `--identity` or `~/.ssh/id_*`), a password only if none
  worked, host keys against `known_hosts`. Every public key goes in *one*
  `AuthMethod`: an ssh client tries each method *name* once, so two publickey
  methods mean an empty agent shadows the key on disk and a device set up with
  `ssh-copy-id` is asked for a password anyway. `--ssh` switches to the host
  binary for what a library cannot do (a `~/.ssh/config` alias, ProxyJump, a
  smartcard); that transport multiplexes over a control socket for the same
  reason.
- **adb** — `github.com/electricbubble/gadb`, which speaks the adb *server*
  protocol. That means a server must be running: the `adb` binary is used for
  exactly one thing, `start-server`, and its absence is reported as a different
  failure from "no device". Note gadb's `DefaultAdbReadTimeout` is a count that
  gets multiplied by `time.Second` where the deadline is set, so it is left
  alone rather than "fixed" into five minutes of seconds.

Partition bytes need no encoding over ssh — the channel is 8-bit clean and no
tty is allocated — but do over adb, whose legacy shell service is a text channel
that has translated line endings on some devices.

## Distributions are data

Where a Linux distribution keeps its own device definition is a table, not a
type hierarchy: a file in one of a few places, in one of a few formats, under
one of a few key spellings. That lives in `catalog/distros.yaml`, loaded with the
rest of the reference data, so supporting another distribution is an entry rather
than a release. The collection script asks for the union of every profile's
candidate paths in one round trip and the matched profile decides which it
wanted. Only *paths* come from data — never a command — so the table can extend
what is read without extending what is run.

What is not a table:

- **Versions.** A distribution moves its own files between releases
  (postmarketOS moved `deviceinfo` out of `/etc`), so a candidate carries
  `since`/`until` bounds compared against `VERSION_ID`. A rolling release whose
  version does not parse ("edge") is treated as newest, which is what it is.
- **Preconditions.** What a recon can see depends on what is installed: without
  its device package a postmarketOS install has no `deviceinfo` at all. Those
  are reported as gaps with the fix named, because "no codename" on its own
  sends the operator looking in the wrong place.
- **Anything conditional on more than one input.** `distro.Profile` is an
  interface; `Distro` is its YAML-backed implementation, and a distribution that
  needs real logic is a Go type passed to `distro.Register`. Droidian and Ubuntu
  Touch are the likely first ones: both keep device identity in an Android
  property system inside a container, which is a different reading of the same
  device rather than another file to parse.

## Command layer

One driver, `runTransportRecon(tr, flags, printSections)`:

1. seed the Bag with the catalog, then `tr.Sources(bag)`
2. `--against` reads a package into the same Bag
3. the route's own report sections (the only part per-route)
4. `--read-partitions`: assert `PartitionLister` + `PartitionReader`, settle
   privileges *once* (`PrepareReads`), select the identity partitions, read them
   smallest-first and offer each to the recognizers
5. resolve the graph; print facts, cross-checks, gaps, `--why`

Which partitions are worth reading is a property of the recon, not the route, so
`transport.IdentityPartitions` and `transport.Ingest` are neutral: a new reader
inherits the allowlist, the size cap, the booted-slot rule, the smallest-first
order and the give-up-after-three-failures rule by implementing one method.

## Open

- **EDL and Odin adapters** — the seam is shaped for them; see the table.
- **A file that lists partitions.** A GPT dump or a stock package does have a
  partition table, and "reading a partition" from a package is reading a member.
  Implementing `PartitionLister`/`PartitionReader` on `imgfacts.File` would make
  package-vs-device comparison work partition by partition, not just fact by
  fact.
- **Vendor providers over the booted routes.** `ro.boot.cid` on a Motorola
  device is the CID, but reading it that way is Motorola knowledge and belongs
  behind the vendor seam over `source:device.adb`, not in the neutral core.
- **Write verbs.** The seam itself is read-only, and the one write verb that
  exists sits beside it rather than in it: `adb debloat` changes *per-user
  package state* (`pm uninstall --user 0`), which writes no partition and is
  undone by a record or a factory reset. That is a different kind of act from
  flashing, and keeping it out of `Transport` is what stops the two being
  confused. Flashing over a route (`PartitionWriter`, `ModeSwitcher`) remains a
  separate decision with a confirm-gate design of its own.
