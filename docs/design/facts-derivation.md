# Fact derivation graph

A design for turning go-unbrick's ad-hoc information extraction into a declared,
composable graph: vendors declare **what facts they can derive and from where**,
and a planner **chains** those derivations to reach a target fact, **cross-checks**
a fact reached by more than one path, or computes the **cheapest path to every
reachable fact**.

Status: proposed. Not built. This captures the design agreed in discussion.

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
  `source:device.fastboot`, `source:stock.zip`, `source:cid.dump`,
  `source:vbmeta.img`, `source:signing_info`. A source "resolves" to itself.

- **Fact key (typed)** — a fact name carrying its value type at compile time, so
  providers and consumers are type-safe while the graph core stays untyped:

  ```go
  type Fact[T any] struct {
      name  string
      equal func(a, b T) bool // optional; verification defaults to ==
  }
  func (f Fact[T]) Name() string { return f.name }

  // Defined ONCE, in one file (facts_keys.go) — the single place name↔type is
  // fixed. A duplicate key with a different T is the only footgun, and grep-obvious.
  var (
      CID             = Fact[uint16]{name: "cid"}
      Carrier         = Fact[string]{name: "carrier"}
      SecurityVersion = Fact[int]{name: "security_version"}
      BootCertChain   = Fact[[]rsakey.Cert]{name: "boot_cert_chain", equal: certSetEqual}
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
  or explicit `Check`s produce findings.
- **Agreement is not a finding** — it is corroboration carried on the winning
  value (its list of agreeing sources); confidence ≈ agreeing-source count ×
  authority.

## Vendor seam

Providers are contributed through the existing seam so all Motorola knowledge
stays behind it:

```go
// in internal/vendor
func Providers() []facts.Provider
func Checks() []facts.Check     // cross-fact invariants (salt==uid, foreign-cid)
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
  `Provider`, and the planner. No vendor knowledge.
- Existing parsers stay and become the bodies of providers:
  `vendor.ParseFlashfile`, `ParseSigningInfo`, `ParseSLCF`, `CIDParse/CIDVersion`,
  `ParseHABMeta`, `rsakey.Scan`, `catalog.CarrierIDName`, `fastboot` getvar/oem.
- `recon` and `fastboot recon` become: collect source facts → `facts.ResolveAll`
  → render the `Bag` (+ findings). Current output is preserved; the hand-written
  cross-checks delete in favor of the verify pass.

## Phasing

1. **Core** — `internal/facts` (types + cost-ordered planner + the same-fact
   verify pass + `Finding`/`Check`). Unit-test the planner with fake providers
   (cheapest path, chaining, disagreement) and a fake check.
2. **First providers** — wrap CID, carrier, codename, signing_cid,
   security_version behind `vendor.Providers()`. Keep everything else as-is.
3. **Adopt in recon** — feed the stock-zip path through the planner; register the
   first `Check` (foreign-`cid`) via `vendor.Checks()`; diff output against today
   to confirm parity, and confirm the hand-written cross-checks can be deleted.
4. **`--why <fact>`** — print the derivation path plus every corroborating source
   ("cid 0x0033 — flashfile.xml cid_value [attested]; getvar cid [attested,
   agrees]; HAB_META says 0x0032 [signing/base, different fact]").
5. **Fill out** — remaining facts/providers; wire `fastboot recon` too; add
   `--verify` to force redundant paths.

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
