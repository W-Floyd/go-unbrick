package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"go-unbrick/internal/adb"
	"go-unbrick/internal/provision"
)

// Provisioning a device over adb: install an app, give it the privileges it
// needs, configure it headlessly, and check that it took.
//
// The recipes are data (catalog/provision.yaml) and the verbs are code, so what
// a recipe can do is bounded by what this tool implements — and what it is
// *about* to do is printed in full, as the exact commands, before anything
// runs. One step in the FreeKiosk recipe cannot be undone on the device at all
// (`dpm set-device-owner` needs a factory reset to clear), which is why that
// one is marked in the plan and confirmed on its own.
func newADBProvisionCmd(o *adb.Options) *cobra.Command {
	var apply, yes, list, noDownload, fetchOnly bool
	var vars, apks, assets, tags []string
	var record, cacheDir string
	var skip, only []string

	c := &cobra.Command{
		Use:   "provision [recipe]",
		Short: "set up a device from a recipe: install, grant, configure, verify",
		Long: `Provision a device over adb from a recipe in catalog/provision.yaml.

A recipe is a sequence of verbs this tool implements — install, device_owner,
grant, appop, start, settings, disable, enable, verify — with values filled in
from --var. It cannot name a shell command to run, by design.

The default run prints every command it would send, in order, with the
irreversible steps marked, and the exact release asset it would fetch — and
changes nothing. --apply downloads what is needed and runs the plan, stopping at
the first failure, and writes a record of what was done.

    unbrick adb provision --list
    unbrick adb provision ha-kiosk --var pin=1234
    unbrick adb provision ha-kiosk --var pin=1234 --apply
    unbrick adb provision ha-kiosk --var pin=1234 --fetch-only    # stage the APKs
    unbrick adb provision freekiosk --var url=https://dash.local --var pin=1234 \
        --apk ~/Downloads/freekiosk.apk --skip device_owner --apply

APKs come from the source the recipe names (a GitHub project's latest release,
or a direct URL) into <library>/apks, keyed by release tag. The plan names the
asset, tag, size and URL before anything is transferred; --apk uses a file you
already have instead, --no-download refuses the network, and --fetch-only stages
the downloads without touching the device. A recipe may pin sha256, which is
verified before install; where it does not, the run prints the digest of what it
installed so you can pin it.

Secrets: a value marked secret in the recipe (a PIN, an API key) travels as an
intent extra, so it is visible on the device's own command line and in logcat
while the app starts. Such commands are printed masked and are left out of the
record.`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			// Recipes are scoped by vendor, so listing without a device shows
			// everything and a run scopes to the device that is attached.
			set := provision.New(activeCatalog().Provision(), "")
			if list || len(args) == 0 {
				return listProvisionRecipes(set)
			}
			prof, ok := set.Get(args[0])
			if !ok {
				return fmt.Errorf("no recipe %q (see `unbrick adb provision --list`)", args[0])
			}
			kv, err := parseVars(vars)
			if err != nil {
				return err
			}
			files, err := parseAPKs(apks)
			if err != nil {
				return err
			}
			assetOf, err := parseVars(assets)
			if err != nil {
				return fmt.Errorf("--asset: %w", err)
			}
			tagOf, err := parseVars(tags)
			if err != nil {
				return fmt.Errorf("--tag: %w", err)
			}
			cache := cacheDir
			if cache == "" {
				cache = filepath.Join(libraryDir(), "apks")
			}
			fetcher := &provision.Fetcher{
				CacheDir:      cache,
				Offline:       noDownload,
				AssetOverride: assetOf,
				TagOverride:   tagOf,
			}
			// Staging the APKs is useful on its own — before taking a device to
			// a bench with no network, or just to get a digest to pin — and it
			// needs no device, so it does not open a connection to one.
			if fetchOnly {
				return runProvisionFetch(prof, kv, files, fetcher)
			}
			return runADBProvision(*o, prof, provisionOpts{
				vars:   kv,
				apks:   files,
				skip:   skip,
				only:   only,
				apply:  apply,
				yes:    yes,
				fetch:  fetcher,
				record: record,
			})
		},
	}
	c.Flags().BoolVar(&list, "list", false, "list the recipes and the vars each one takes")
	c.Flags().StringArrayVar(&vars, "var", nil, "recipe value as name=value, repeatable")
	c.Flags().StringArrayVar(&apks, "apk", nil,
		"use a local APK instead of fetching, as <path> or <name>=<path> for a recipe that installs several")
	c.Flags().StringArrayVar(&assets, "asset", nil,
		"override which release asset to fetch, as <name>=<glob> (e.g. --asset ha=app-minimal-release.apk)")
	c.Flags().StringArrayVar(&tags, "tag", nil, "override the release tag to fetch, as <name>=<tag> (default: the latest release)")
	c.Flags().BoolVar(&noDownload, "no-download", false, "never reach the network: use the APK cache or --apk only")
	c.Flags().BoolVar(&fetchOnly, "fetch-only", false,
		"download the recipe's APKs into the cache and stop, without touching the device (prints each digest, for pinning)")
	c.Flags().StringVar(&cacheDir, "apk-cache", "", "where downloaded APKs are kept (default <library>/apks)")
	c.Flags().StringArrayVar(&skip, "skip", nil, "skip a verb, e.g. --skip device_owner (repeatable)")
	c.Flags().StringArrayVar(&only, "only", nil,
		"run only these verbs, e.g. --only install to update the APKs on an already-provisioned device (repeatable)")
	c.Flags().BoolVar(&apply, "apply", false, "actually run the plan (default: print it and stop)")
	c.Flags().BoolVar(&yes, "yes", false, "skip the typed confirmations")
	c.Flags().StringVar(&record, "record", "", "where to write the record (default provision-<recipe>-<serial>.json)")
	return c
}

type provisionOpts struct {
	vars   map[string]string
	apks   map[string]string
	skip   []string
	only   []string
	apply  bool
	yes    bool
	fetch  *provision.Fetcher
	record string
}

// parseAPKs reads the --apk values: a bare path for a recipe with one APK, or
// name=path for one that installs several.
func parseAPKs(vals []string) (map[string]string, error) {
	out := map[string]string{}
	for _, v := range vals {
		name, path, ok := strings.Cut(v, "=")
		if !ok {
			// A bare path is the unnamed APK. A Windows-style path would confuse
			// this, but adb's own world is POSIX paths.
			name, path = "", v
		}
		if strings.TrimSpace(path) == "" {
			return nil, fmt.Errorf("--apk %q has no file", v)
		}
		if _, err := os.Stat(path); err != nil {
			return nil, fmt.Errorf("--apk %s: %w", v, err)
		}
		out[strings.TrimSpace(name)] = path
	}
	return out, nil
}

func listProvisionRecipes(set *provision.Set) error {
	profs := set.Profiles()
	if len(profs) == 0 {
		return fmt.Errorf("no recipes in catalog/provision.yaml")
	}
	fmt.Println(cHdr("  Provisioning recipes:"))
	for _, p := range profs {
		fmt.Printf("    %s — %s\n", cTag(p.ID), p.Name)
		if p.Doc != "" {
			fmt.Printf("      docs: %s\n", p.Doc)
		}
		for _, name := range apkSourceLines(p) {
			fmt.Printf("      %s\n", name)
		}
		for _, v := range p.Vars {
			req := ""
			if v.Required {
				req = cWarn(" (required)")
			}
			if v.Default != "" {
				req = fmt.Sprintf(" (default %s)", v.Default)
			}
			fmt.Printf("      --var %s%s\n", v.Name, req)
			if v.Note != "" {
				fmt.Printf("          %s\n", squash(v.Note))
			}
		}
	}
	return nil
}

// runProvisionFetch downloads a recipe's APKs and stops. No device is opened:
// staging files is a local act, and pretending otherwise would make the command
// fail on a bench with no phone attached.
func runProvisionFetch(prof *provision.Profile, vars, given map[string]string, fetcher *provision.Fetcher) error {
	actions, err := prof.Render(vars)
	if err != nil {
		return err
	}
	sources, err := fetcher.Resolve(prof, actions, given)
	if err != nil {
		return err
	}
	if len(sources) == 0 {
		return fmt.Errorf("nothing to fetch: %s installs no APK, or every one was given with --apk", prof.ID)
	}
	fmt.Printf("Recipe: %s — %s\n\n", prof.ID, prof.Name)
	for _, s := range sources {
		if !s.Have {
			progressLine("downloading %s (%s)…", s.Name, formatSizeKB(uint64(s.Size)/1024))
		}
		path, digest, err := fetcher.Get(s)
		clearProgressLine()
		if err != nil {
			return err
		}
		state := "downloaded"
		if s.Have {
			state = "cached"
		}
		fmt.Printf("  %s %s (%s)\n", cGood("✓"), s.Name, state)
		fmt.Printf("      %s\n", path)
		fmt.Printf("      sha256: %s\n", digest)
	}
	fmt.Println("\n  Pin a build by putting its digest in the recipe's `sha256:`.")
	fmt.Println("  Install with --apply; add --no-download to refuse any further fetching.")
	return nil
}

func runADBProvision(o adb.Options, prof *provision.Profile, f provisionOpts) error {
	actions, err := prof.Render(f.vars)
	if err != nil {
		return err
	}
	actions = selectActions(actions, f.skip, f.only)
	if len(actions) == 0 {
		return fmt.Errorf("no steps left to run after --skip/--only")
	}

	dev, err := adb.Open(o)
	if err != nil {
		return err
	}
	defer dev.Close()

	// A recipe scoped to another OEM is refused here rather than half-run: the
	// device is what settles whose recipe this is.
	vendorID := dev.R.VendorID()
	if _, ok := provision.New([]*provision.Profile{prof}, vendorID).Get(prof.ID); !ok {
		return fmt.Errorf("recipe %s is for %s devices, and this one is %s",
			prof.ID, prof.Vendor, orUnknown(vendorID))
	}

	fmt.Printf("Android Device: %s  (%s, carrier %s)\n", dev.R.Serial,
		orUnknown(dev.R.Props["ro.build.display.id"]), orUnknown(dev.R.Props["ro.carrier"]))
	fmt.Printf("Recipe: %s — %s\n", prof.ID, prof.Name)
	if prof.Doc != "" {
		fmt.Printf("        %s\n", prof.Doc)
	}

	// Preconditions first: the irreversible step fails late and cryptically
	// when they are unmet, and a half-provisioned kiosk is worse than one that
	// never started.
	checks := provision.Preflight(dev, prof, actions)
	if len(checks) > 0 {
		fmt.Println("\n" + cHdr("  Preflight:"))
		for _, ch := range checks {
			mark := cGood("✓")
			if !ch.OK {
				mark = cWarn("!")
				if ch.Fatal {
					mark = cBad("✗")
				}
			}
			fmt.Printf("    %s %-34s %s\n", mark, ch.What, ch.Says)
			// The remedy goes with the failure, not in a paragraph elsewhere.
			if !ch.OK && ch.Fix != "" {
				fmt.Printf("      %s\n", cTag("fix:")+" "+squash(ch.Fix))
			}
		}
	}

	// What will be fetched, resolved to an exact asset and release before
	// anything is transferred. Metadata only: the download itself waits for
	// --apply.
	var sources []provision.Source
	if f.fetch != nil {
		var rerr error
		sources, rerr = f.fetch.Resolve(prof, actions, f.apks)
		if rerr != nil {
			return rerr
		}
	}
	if len(sources) > 0 {
		fmt.Println("\n" + cHdr("  APKs to fetch:"))
		for _, s := range sources {
			mark := " "
			if s.Have {
				mark = cGood("✓")
			}
			fmt.Printf("    %s %s\n", mark, s.Describe())
			if s.Size > 0 && !s.Have {
				fmt.Printf("      %s → %s\n", formatSizeKB(uint64(s.Size)/1024), s.Cached)
			}
		}
		if !anyPinned(prof) {
			fmt.Printf("    %s\n", cWarn("This recipe pins no digest, so it installs whatever that release currently holds."))
			fmt.Printf("    %s\n", cWarn("The run prints the sha256 of what it installed; put it in the recipe to pin it."))
		}
	}

	fmt.Println("\n" + cHdr("  Plan:"))
	for i, a := range actions {
		tag := ""
		if a.Irreversible {
			tag = " " + cBad("[irreversible]")
		}
		fmt.Printf("    %d. %s%s\n", i+1, a.Describe, tag)
		// A manual step has no command; printing a placeholder one would
		// suggest otherwise.
		if !a.Manual {
			fmt.Printf("       $ adb shell %s\n", withResolvedAPK(maskSecret(a), a, f.apks, sources))
		}
		if a.Note != "" {
			fmt.Printf("       %s\n", squash(a.Note))
		}
	}
	for _, n := range prof.Notes {
		fmt.Printf("\n    %s\n", squash(n))
	}

	if provision.Fatal(checks) {
		// Repeat the remedy in the error: the plan above may have scrolled, and
		// the last line is the one that gets read.
		for _, ch := range checks {
			if ch.Fatal && ch.Fix != "" {
				return fmt.Errorf("%s: %s", ch.What, squash(ch.Fix))
			}
		}
		return fmt.Errorf("a precondition this recipe requires is not met — fix it, or re-run with --skip for the step that needs it")
	}
	if !f.apply {
		fmt.Println("\n    Nothing was changed. Add --apply to run this.")
		return nil
	}

	// Two confirmations, because they are two different decisions: running the
	// recipe, and taking an irreversible step on this device.
	if !f.yes {
		fmt.Printf("\nAbout to run %d steps on %s. Type 'provision' to proceed: ", len(actions), dev.R.Serial)
		if !confirm("provision") {
			return fmt.Errorf("aborted")
		}
		for _, a := range actions {
			if !a.Irreversible {
				continue
			}
			fmt.Printf("\n%s\n", cBad("  "+a.Describe+" cannot be undone on this device:"))
			fmt.Printf("%s\n", cBad("  clearing it needs a factory reset. "+squash(a.Note)))
			fmt.Print("Type 'irreversible' to accept that step: ")
			if !confirm("irreversible") {
				return fmt.Errorf("aborted")
			}
		}
	}

	fmt.Println()
	rec, runErr := provision.Apply(dev, prof, actions, f.apks, provision.Hooks{
		Progress: func(i, n int, a provision.Action) {
			progressLine("step %d/%d: %s", i+1, n, a.Describe)
		},
		// Fetching happens here, under --apply, from the sources the plan
		// already named.
		Fetch: func(name string) (string, string, error) {
			if f.fetch == nil {
				return "", "", fmt.Errorf("no fetcher")
			}
			for _, s := range sources {
				if s.APK != name {
					continue
				}
				if !s.Have {
					progressLine("downloading %s (%s)…", s.Name, formatSizeKB(uint64(s.Size)/1024))
				}
				path, digest, err := f.fetch.Get(s)
				clearProgressLine()
				if err == nil {
					fmt.Printf("  %s %s  sha256 %s\n", cGood("↓"), s.Name, digest)
				}
				return path, digest, err
			}
			return "", "", fmt.Errorf("nothing resolved for %s: pass it with --apk %s=<file>", name, name)
		},
		// A manual step is where the flow waits for the person at the device.
		// Pausing is the honest thing: the alternative is a kiosk locked onto
		// an app that was never signed in.
		Pause: func(a provision.Action) bool {
			clearProgressLine()
			fmt.Printf("\n  %s\n", cTag("do this on the device:"))
			fmt.Printf("    %s\n", squash(strings.TrimPrefix(a.Describe, "you: ")))
			if a.Note != "" {
				fmt.Printf("    %s\n", squash(a.Note))
			}
			fmt.Print("  Type 'done' when it is done (anything else stops here): ")
			return confirm("done")
		},
	})
	clearProgressLine()
	for _, r := range rec.Actions {
		switch {
		case r.Err != "":
			fmt.Printf("  %s %s\n    %s\n", cBad("✗"), r.Describe, r.Err)
		default:
			fmt.Printf("  %s %s\n", cGood("✓"), r.Describe)
		}
	}

	path := f.record
	if path == "" {
		path = fmt.Sprintf("provision-%s-%s.json", sanitize(prof.ID), sanitize(dev.R.Serial))
	}
	if fh, err := os.Create(path); err == nil {
		defer fh.Close()
		if werr := provision.WriteRecord(fh, rec); werr == nil {
			fmt.Printf("\n  Record: %s\n", path)
		}
	}
	// What went on the device, by digest, so a later run can pin exactly this.
	if len(rec.Installed) > 0 {
		fmt.Println("\n" + cHdr("  Installed:"))
		for _, in := range rec.Installed {
			fmt.Printf("    %-28s %s\n", orUnknown(in.APK)+":", in.File)
			fmt.Printf("      sha256: %s\n", in.SHA256)
		}
		fmt.Println("    Put a digest in the recipe's `sha256:` to pin that exact build.")
	}
	if len(rec.Irreversible) > 0 {
		fmt.Printf("  %s\n", cWarn("This device now has: "+strings.Join(rec.Irreversible, ", ")+
			" — a factory reset is the way to undo that."))
	}
	return runErr
}

// apkSourceLines describes where a recipe's APKs come from, for --list. Every
// line says whether the build is pinned, because that is the difference between
// "this app" and "this build of this app".
func apkSourceLines(p *provision.Profile) []string {
	describe := func(name string, spec provision.APKSpec) string {
		label := "APK"
		if name != "" {
			label = "APK " + name
		}
		line := fmt.Sprintf("%s: %s", label, spec.Source)
		if spec.Asset != "" {
			line += " → " + spec.Asset
		}
		if spec.Tag != "" && spec.Tag != "latest" {
			line += " @" + spec.Tag
		}
		if spec.SHA256 != "" {
			line += "  (pinned)"
		} else {
			line += "  (latest release, unpinned)"
		}
		return line
	}
	var out []string
	if p.APK.Source != "" {
		out = append(out, describe("", p.APK))
	}
	for _, name := range sortedMapKeys(p.APKs) {
		out = append(out, describe(name, p.APKs[name]))
	}
	return out
}

func sortedMapKeys(m map[string]provision.APKSpec) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// withResolvedAPK replaces an install step's placeholder with the file that
// will actually be installed — the one passed with --apk, or the asset the
// fetch resolved. A plan that still says "<--apk ha=<file>>" next to a resolved
// download reads as if the operator had to supply it.
func withResolvedAPK(cmd string, a provision.Action, given map[string]string, sources []provision.Source) string {
	if !a.Install {
		return cmd
	}
	placeholder := "<--apk <file>>"
	if a.APKName != "" {
		placeholder = fmt.Sprintf("<--apk %s=<file>>", a.APKName)
	}
	if path := given[a.APKName]; path != "" {
		return strings.Replace(cmd, placeholder, path, 1)
	}
	for _, s := range sources {
		if s.APK == a.APKName {
			return strings.Replace(cmd, placeholder, s.Cached, 1)
		}
	}
	return cmd
}

// anyPinned reports whether a recipe pins any digest, which decides whether the
// plan warns that a fetch takes whatever upstream currently publishes.
func anyPinned(p *provision.Profile) bool {
	if p.APK.SHA256 != "" {
		return true
	}
	for _, spec := range p.APKs {
		if spec.SHA256 != "" {
			return true
		}
	}
	return false
}

// maskSecret keeps a PIN or an API key out of the terminal while still showing
// the shape of the command that carries it. The masking is done where the
// command is rendered; this only labels it.
func maskSecret(a provision.Action) string {
	if !a.Secret {
		return a.Command
	}
	return a.Print() + "   " + cWarn("(masked)")
}

// selectActions applies --skip and --only, matched on the verb rather than on
// the prose of a step's description.
//
// --only is what makes a re-run useful: `--only install` reinstalls the APKs
// over an already-provisioned device, which is how a sideloaded app is updated
// without touching its configuration or the device owner.
func selectActions(actions []provision.Action, skip, only []string) []provision.Action {
	verbs := func(list []string) map[string]bool {
		out := map[string]bool{}
		for _, s := range list {
			out[strings.ToLower(strings.TrimSpace(strings.ReplaceAll(s, "-", "_")))] = true
		}
		return out
	}
	drop, keep := verbs(skip), verbs(only)
	if len(drop) == 0 && len(keep) == 0 {
		return actions
	}
	var out []provision.Action
	for _, a := range actions {
		verb := provisionVerb(a)
		switch {
		case drop[verb]:
			fmt.Printf("  %s\n", cWarn("[skipped] "+a.Describe))
		case len(keep) > 0 && !keep[verb]:
			// Quietly left out: --only names what to do, and listing everything
			// it excluded would bury that.
		default:
			out = append(out, a)
		}
	}
	return out
}

// provisionVerb names an action for --skip. It reads the command, which is the
// thing an operator sees and would name.
func provisionVerb(a provision.Action) string {
	switch {
	case a.Install:
		return "install"
	case strings.HasPrefix(a.Command, "dpm set-device-owner"):
		return "device_owner"
	case strings.HasPrefix(a.Command, "dpm remove-active-admin"):
		return "device_owner"
	case strings.HasPrefix(a.Command, "pm grant"):
		return "grant"
	case strings.HasPrefix(a.Command, "appops"):
		return "appop"
	case strings.HasPrefix(a.Command, "am start"):
		return "start"
	case strings.HasPrefix(a.Command, "settings put"):
		return "settings"
	case a.Verify != nil:
		return "verify"
	}
	return ""
}

// parseVars reads the --var name=value pairs.
func parseVars(vals []string) (map[string]string, error) {
	out := map[string]string{}
	for _, v := range vals {
		name, value, ok := strings.Cut(v, "=")
		if !ok || strings.TrimSpace(name) == "" {
			return nil, fmt.Errorf("--var %q is not name=value", v)
		}
		out[strings.TrimSpace(name)] = value
	}
	return out, nil
}
