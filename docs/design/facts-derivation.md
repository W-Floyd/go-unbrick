# Fact derivation graph

A design for turning go-unbrick's ad-hoc information extraction into a declared,
composable graph: vendors declare **what facts they can derive and from where**,
and a planner **chains** those derivations to reach a target fact, **cross-checks**
a fact reached by more than one path, or computes the **cheapest path to every
reachable fact**.

Status: built. `internal/facts`, the neutral device providers, Motorola's
providers and checks, both recons (`recon` and `fastboot recon`), `--why` and
`--verify`. What is left is breadth — more facts and providers — not structure.

## Why

The same fact is reachable from several places, and today each path is hand-wired:

| Fact | Paths we already extract |
|---|---|
| carrier CID | `fastboot getvar cid`; `flashfile.xml` `cid_value`; the `cid` partition (v2 record); (base/signing CID from `vbmeta` HAB_META and `signing-info.txt`) |
| codename | HAB_META; `flashfile.xml` software_version; getvar `product` |
| SoC | JTAG_ID → catalog; getvar `cpu`; ELF `QCVersion` |
| security / anti-rollback version | `signing-info.txt` HAB_SECURITY_VERSION; `oem read_sv`; per-image table in signing-info |
| subsidy lock | `slcf_*.nvm`; `flashfile.xml` subsidy_lock_config name; live carrier partition |
| unlock challenge | `oem get_unlock_data`; reconstructed from the `cid` partition record |
| boot cert chain | every signed ELF/`.mbn` (rsakey); OTA cert from recovery `otacerts.zip` |

Consequences of hand-wiring: cross-checks are one-off (`salt==UID`, HAB-CID ≠
carrier-CID, `read_sv` vs signing-info), the "which source is authoritative" rule
lives in prose, and `recon` / `fastboot recon` each re-implement assembly.

Formalizing gives: automatic cross-verification, a single authority order, a
"why/how do we know X" trace, and thin recon commands that just render the result.

## Model

- **Fact** — a named datum. Start small and typed:
  `cid`, `signing_cid`, `carrier`, `channel`, `codename`, `model`, `soc`,
  `security_version`, `anti_rollback_table`, `subsidy_lock`, `unlock_challenge`,
  `ota_key`, `boot_cert_chain`, `lock_state`, `slot`, `build_fingerprint`.

- **Source** — an input, expressed as a leaf fact you already hold, e.g.
  `source:stock.zip`, `source:vbmeta.img`, `source:catalog`,
  `source:device.recon` (a bootloader's `getvar all`), `source:device.linux` (an
  ssh-reachable install), `source:device.adb` (an Android userspace). Which
  routes exist and what each can honestly answer is
  [transports.md](transports.md); a source is what a route *deposits*. A source "resolves"
  to itself. A source that is one OEM's *format* (`source:flashfile.xml`,
  `source:signing-info.txt`, `source:slcf`, `source:cid.dump`) is declared behind
  that vendor's seam, not in the core: the core names only the container, the
  AOSP formats and the reference data. `facts.Key` binds a name to one type
  wherever it is declared, and panics at init on a second binding.

- **Recognizer** — how a source gets into the Bag. Nothing asks a package for a
  member by name: ingestion walks what the file actually contains and offers
  each one to the recognizers, which decide what it is by handing the bytes to
  the parser that would claim them — a manifest is a manifest because the
  manifest parser gets something out of it. Vendors contribute recognizers
  through the same seam as providers, so a package that spells its members
  differently still yields its facts.

  ```go
  type File struct{ Name string; Data []byte; From string; Top bool }
  type Recognizer func(b *Bag, f File) []string // the sources it set
  ```

  `Top` marks the file the command was pointed at. A source a package holds many
  of — every signed image — is a fact only when it *is* the thing being examined;
  inside a container it is one of a crowd, and "the package's signing chain" is
  not one chain.

- **Fact key (typed)** — a fact name carrying its value type at compile time, so
  providers and consumers are type-safe while the graph core stays untyped:

  ```go
  type Fact[T any] struct {
      name   string
      equal  func(a, b T) bool // Eq:  optional; verification defaults to a deep compare
      format func(T) string    // Fmt: optional; how a report and --why print it
  }
  func (f Fact[T]) Name() string { return f.name }

  // Key declares a key and binds name↔type in a registry shared across the seam,
  // so the duplicate-name-different-type footgun panics at init instead of
  // silently making Get miss. The core declares the common set (keys.go); a
  // vendor declares its own the same way.
  var (
      CID             = Key[uint16]("cid", Fmt(hexCID))
      Carrier         = Key[string]("carrier")
      SecurityVersion = Key[int]("security_version")
      BootCertChain   = Key[[]rsakey.Cert]("boot_cert_chain", Eq(certSetEqual))
  )
  ```

- **Value** — a resolved value with provenance and authority. `Data` is `any` at
  rest; the one and only cast lives in the typed `Get`, so provider bodies never
  touch `interface{}`:

  ```go
  type Value struct {
      Data      any    // read back through Get[T]; never asserted elsewhere
      Source    string // human provenance: "flashfile.xml cid_value"
      Authority Level  // Attested > Derived > Reference(forum)
  }

  func Get[T any](b *Bag, f Fact[T]) (T, bool)          // the sole assertion site
  func Set[T any](b *Bag, f Fact[T], v T, p Provenance) // typed write
  ```

- **Bag** — values keyed by fact name, `map[string][]Value`. Keeps *all* values
  per fact (not just one) so corroboration and disagreement are both visible.

- **Provider** — non-generic, so a heterogeneous set lives in one graph (Go can't
  hold `Provider[uint16]` and `Provider[string]` together). It names its edges as
  strings; its `Derive` body reads/writes the Bag through the typed `Get`/`Set`:

  ```go
  type Provider interface {
      Provides() string   // Fact.Name()
      Requires() []string // other facts / leaf sources it consumes
      Cost() int          // local parse ≪ one paced fastboot round trip
      Authority() Level
      Derive(in *Bag) (bool, error) // ok=false: not present this time
  }
  ```

  This is the deliberate split: **typed at the edges** (keys, `Get`/`Set`,
  provider bodies), **erased in the core** (graph, planner), with a single cast in
  `Get`. Fully-generic providers can't share a graph; raw-`any` bodies lose the
  type safety where bugs live — the hybrid takes the best of both.

  Cost guidance: local byte parse = 1; catalog/library lookup = 1; reading a zip
  member = 5; a paced `getvar` = 100; an `oem` probe = 100; an EDL/partition read
  = 500. (Relative, not absolute — the planner only compares.)

## Findings & checks

A **Finding** is a judgment *about* values (a conflict or a broken invariant), not
a value — so it lives in its own channel, referencing Bag values rather than
copying them. The report renders the Bag, then the findings (values first, then
`[!]` warnings, as recon already does).

```go
type Finding struct {
    Severity Severity  // Warn: same-fact conflict; Error: invariant broken
    Facts    []string  // fact(s) involved
    Message  string
    Values   []Value   // the conflicting/relevant values (source + authority)
}

type Result struct {
    Bag      *Bag
    Findings []Finding
}
```

Findings arise two ways:

- **Same-fact conflict — automatic.** The Bag holds every value per fact; the
  resolve pass compares them (key `equal`, default `==`). On mismatch it emits a
  `Warn`, and **authority picks the displayed value** (attested package over a
  mutable device read — the transplanted-`cid` case). Equal-authority conflict is
  a louder `Warn` (genuinely ambiguous).
- **Cross-fact invariant — declared.** A relationship *between different facts*
  that must hold, e.g. `unlock_challenge.salt == device.uid`, or the old
  foreign-`cid` check. These are `Check`s registered behind the seam, not
  hand-wired in recon:

  ```go
  type Check interface {
      Reads() []string          // facts it inspects
      Verify(in *Bag) []Finding
  }
  ```

Two rules that fall out:

- **Different facts that are *expected* to differ are not a conflict.** `signing_cid`
  (HAB base) vs `cid` (carrier) legitimately differ, which is exactly why they are
  separate facts, not one `cid` with a bogus disagreement. Only same-fact values
  or explicit `Check`s produce findings. The rule earns its keep the moment a
  provider is careless: `soc` from the JTAG id ("Qualcomm SM6225") and `getvar
  cpu` ("SM_DIVAR 1.0") are two namespaces for one part, and collapsing them into
  one fact made a live recon report a disagreement between two correct answers.
  They are now `soc` and `platform`.
- **Agreement is not a finding** — it is corroboration carried on the winning
  value (its list of agreeing sources); confidence ≈ agreeing-source count ×
  authority.

## Vendor seam

Providers are contributed through the existing seam so all Motorola knowledge
stays behind it:

```go
// in internal/vendor — gathered from the optional FactDeriver / FactChecker /
// FactRecognizer driver capabilities, the same way fastboot profiles and
// commands are.
func Providers() []facts.Provider
func Checks() []facts.Check           // cross-fact invariants (salt==uid, foreign-cid)
func Recognizers() []facts.Recognizer // what this OEM's formats look like
func FactGraph() *facts.Graph
```

Motorola registers, e.g.:

- `cid ← source:device.fastboot`            (getvar cid)           Attested, cost 100
- `cid ← source:stock.zip`                  (flashfile cid_value)  Attested, cost 5
- `cid ← source:cid.dump`                   (v2 record)            Attested, cost 1
- `signing_cid ← source:vbmeta.img`         (HAB_META)             Derived,  cost 5
- `signing_cid ← source:signing_info`       (HAB_CID)              Attested, cost 1
- `carrier ← cid`                           (catalog carrier_ids)  Attested, cost 1
- `carrier ← cid`                           (cid_reference)        Reference,cost 1
- `security_version ← source:signing_info`  (HAB_SECURITY_VERSION) Attested, cost 1
- `security_version ← source:device.fastboot` (oem read_sv)        Attested, cost 100
- `subsidy_lock ← source:stock.zip`         (slcf_*.nvm)           Attested, cost 5
- `unlock_challenge ← source:cid.dump`      (reconstruct wire)     Attested, cost 1
- `unlock_challenge ← source:device.fastboot` (oem get_unlock_data) Attested, cost 100
- `boot_cert_chain ← source:*`              (rsakey scan)          Attested, cost 5

Generic (cross-vendor) providers can exist too: `boot_cert_chain ← any ELF`,
`ota_key ← recovery otacerts.zip`.

## Planner

Facts are nodes; providers are edges (their `Requires` → `Provides`), weighted by
`Cost`. Given the source facts you hold:

- **Resolve one fact** — Dijkstra from the available sources to the target; run
  the providers along the cheapest satisfiable chain. This is "most efficient
  path to X".
- **Resolve all** — run every provider whose `Requires` are satisfied, cheapest
  first, to a fixpoint. This is "everything reachable from what I have".
- **Verify** — when ≥2 providers can produce the same fact, run them and compare
  values:
  - agree → one value, higher confidence, sources listed.
  - disagree → keep both, emit a **finding** (this is exactly the foreign-CID and
    HAB-CID-≠-carrier-CID checks, generalized).
- **Authority** breaks ties for the *displayed* value (Attested over Reference),
  but a lower-authority value that *disagrees* is still surfaced.

Budget/laziness: for a fact reachable both locally and via a paced probe, the
planner takes the local path unless asked to verify (then it also runs the probe).
A `--verify` flag opts into running redundant paths for cross-checking.

## Mapping onto existing code

- New generic package `internal/facts`: `Fact`, `Value`, `Level`, `Bag`,
  `Provider`, `Recognizer`, and the planner. No vendor knowledge.
- Existing parsers stay and become the bodies of providers *and* of the
  recognizers that decide what a file is: `vendor.ParseFlashfile`,
  `ParseSigningInfo`, `ParseSLCF`, `CIDParse/CIDVersion`, `ParseHABMeta`,
  `rsakey.Scan`, `catalog.CarrierIDName`, `fastboot` getvar/oem.
- `internal/imgfacts` holds the cross-vendor half: `Ingest` (walk a file and its
  members, recognize each) plus the derivations true of any OEM's image —
  `boot_cert_chain`, `ota_certs`, `soc` from an ELF's build string.
- `recon` is: ingest → `ResolveAll` → render the `Bag` → findings, for every file
  kind, not just packages. `fastboot recon` keeps its own report and adds the
  graph's judgments as a `Cross-checks:` section.

## Phasing

1. ~~**Core**~~ — `internal/facts`: types, cost-ordered planner, same-fact verify
   pass, `Finding`/`Check`, tested with fake providers.
2. ~~**First providers**~~ — cid, signing_cid, carrier, codename,
   software_version, security_version, region, customer_signed, ota_key,
   anti-rollback table, subsidy_lock, behind `vendor.Providers()`.
3. ~~**Adopt in recon**~~ — the stock-zip path resolves through the planner and
   renders the Bag. Output is unchanged but for one improvement: the carrier name
   now resolves whether or not `vendor.Detect` claimed the file, because the rule
   belongs to the driver whose table it reads. The first `Check` is the
   region↔signing-CID binding, not foreign-`cid`: that one needs the live device
   and the library, so it stays where it is until `fastboot recon` moves over.
4. ~~**`--why <fact>`**~~ — `recon --why cid` prints the chain and every
   corroborating or contradicting source.
5. ~~**Fill out**~~ — `--verify`; `fastboot.FactProviders()` (the neutral
   `getvar` facts) and Motorola's device rules over `source:device.recon`; the
   salt==UID / foreign-`cid` invariant registered as a `Check`. The command layer
   builds one graph from both halves, so a device fact and a package fact meet in
   one Bag. `fastboot recon` gained a `Cross-checks:` section and `--why`; its
   report is otherwise byte-identical on a live fogona.

   The salt==UID logic is now *shared* rather than deleted: the report line still
   renders the positive "✓ device-bound" annotation the findings channel has no
   place for, but both it and the `Check` call one function, so they cannot drift.

6. ~~**Content-driven ingestion**~~ — the member rules that asked a package for
   "flashfile.xml" are gone; `imgfacts.Ingest` walks what is there and the
   recognizers say what each thing is. Single-file recon goes through the graph
   too, so `recon --why signing_cid vbmeta.img` answers. `boot_cert_chain`,
   `ota_certs` and `soc`-from-an-ELF are the first cross-vendor providers.

   `cid` from a *v2* (signed) cid record is now handled: `CIDCarrier` reads the
   channel as a big-endian u16 at `header_base+2` (base `0x28` for v0/v1, `0x2a`
   for v2), which is exactly what ABL's loader `FUN_0004b340` does — confirmed
   against a real fogona v2 dump whose value `0x0032` matches its HAB_META CID
   (see ../fogona-abl-notes). It is Derived, not Attested: the signature is not
   checked offline, so a transplanted record still loses to a package manifest.
   `readcid` uses the same reader, so it now works on secure-production units
   (the old v0-template-only parser failed on every v2 device).

   The Motorola `.info.txt` build sheet is now a source too: `build_fingerprint`
   (the AOSP fingerprint in the clear — the same identity a device reports over
   getvar, so package-vs-device is cross-checkable), plus `marketing_name`,
   `modem_version` and `mbm_version`. `marketing_name` is deliberately its own
   fact, not folded into `model` (the XT SKU) or `codename` — three names for one
   device in three namespaces.

   Package integrity is now a `Check`: the flashfile declares an MD5/SHA1 per
   member, and `verifyPackageIntegrity` hashes each and compares. It is Heavy
   (the new `VerifyGated` capability) — hashing a 4.4 GiB package takes ~45 s —
   so it runs only under `--verify`; a clean pass is a single `Info` finding, a
   mismatch or missing member an `Error`. The OTA update key (MAP5 OTA, RSA-4096
   in recovery's otacerts.zip) is now `ota_certs`, extracted from any boot-image
   member — ingestion gives boot images a larger read budget (128 MiB) than the
   8 MiB default because recovery is where the key hides. And the build sheet's
   `AB Update Enabled` and `Build Date` become `ab_enabled` / `build_date`.

   Still open: `unlock_challenge ← source:cid.dump`. The wire fields (id, serial,
   target, salt) all sit in a v2 record at fixed offsets (0x30 / 0x38 / 0x50 /
   0x08 on the fogona dump), so reconstructing `id#serial#target#salt` is
   feasible — but those offsets are corroborated by only one sample, so it is
   left as future work rather than shipped on a single data point. And the other
   vendors contribute no providers yet.

7. ~~**More routes to a device**~~ — the graph now takes sources from a booted
   phone as well as a bootloader and a package: `source:device.linux` (ssh to
   postmarketOS and the like) and `source:device.adb` (an Android userspace),
   both behind the transport seam in [transports.md](transports.md). Two things
   fell out of that which are properly facts-layer decisions:

   - **A booted userspace is Derived, not Attested.** It knows more than a
     bootloader does, but everything it says passed through a mutable
     filesystem and a kernel command line the installed system may have
     replaced, so a package manifest or a `getvar` answer wins the display while
     the disagreement still surfaces. The exception is the identity of the
     install itself (`device_os`, `kernel_release`), where the running system is
     the only authority there is.
   - **Partition content is a source, not a special case.** With root, a booted
     device hands over the identity and boot-chain partitions, and those bytes
     go to the same recognizers a package's members do — so `cid`, `vbmeta`,
     `xbl` and the rest derive `cid`, `avb_key`, `avb_rollback_index`,
     `signing_cid` and `boot_cert_chain` through the rules that already existed.
     Verified on a fogona running postmarketOS: sixteen partitions read over
     ssh, and CID `0x0032`, HAB CID 50 and AVB rollback 18 resolved from their
     content with no new derivations written.

   Two namespace lessons repeated themselves here, which is why they are rules
   rather than anecdotes: a mainline kernel puts the *board model* in
   `/sys/devices/soc0/machine`, and a device tree lists the SoC families it also
   binds to after the part it is — so SoC tokens are filtered to things that
   look like part numbers and only the first compatible entry is a claim.
   Feeding either of the others into `soc` manufactured a disagreement between
   correct answers, exactly as collapsing `soc` and `platform` once did.

## Open questions

- ~~Typed fact values vs `any`.~~ **Decided (see Model):** hybrid — typed
  `Fact[T]` keys + generic `Get[T]/Set[T]` over an `any`-backed Bag, non-generic
  `Provider`. Verification compares with `==` by default, or the key's optional
  `equal` for complex facts (e.g. cert chains compared by SPKI-fingerprint set).
- ~~Where "authority" lives.~~ **Decided:** the provider declares it
  (`Authority() Level`) — authority is a property of *how* a value was derived,
  which the provider knows. Note the consequence: a provider that reads a mutable
  device partition (e.g. a `cid` that could be transplanted) should declare a
  lower authority than one parsing a package's attested manifest, so a disagreement
  surfaces the package value as canonical while still flagging the device value.
- ~~Findings in the Bag or a separate channel.~~ **Decided (see Findings &
  checks):** a separate `Findings` channel that *references* Bag values; findings
  are judgments about values, not values. Same-fact conflicts are emitted
  automatically; cross-fact invariants are declared `Check`s behind the seam;
  agreement is not a finding (just corroboration on the winning value).
