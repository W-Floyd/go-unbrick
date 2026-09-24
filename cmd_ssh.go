package main

import (
	"fmt"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"go-unbrick/internal/catalog"
	"go-unbrick/internal/distro"
	"go-unbrick/internal/library"
	"go-unbrick/internal/linuxdev"
)

// The ssh route: a phone booted into a Linux distribution (postmarketOS,
// Mobian, any of them). `recon` reads a file and `fastboot recon` asks a
// bootloader; this asks a running install. The graph behind all of them is the
// same, so what a distribution says is cross-checked against what a package or
// a bootloader said by one set of rules.
// sshPasswordHelp is on both the group and the recon subcommand, since either
// is where an operator lands with `--help` and a device that wants a password.
// There is deliberately no --password flag: a command line is readable by every
// process on the host and ends up in the shell history besides.
var sshPasswordHelp = fmt.Sprintf(`Passwords: typed at the prompt, or taken from %[1]s for an
unattended run. The same password is offered to sudo on the device when
--read-partitions has to elevate, so one answer covers both:

    %[1]s=… unbrick ssh recon user@phone --read-partitions

A device set up with ssh-copy-id needs no password at all, and neither does a
login with passwordless doas/sudo. A passphrase-protected key is a different
secret and is always prompted for — load it into the ssh agent for an unattended
run.`, linuxdev.PasswordEnv)

func newSSHCmd() *cobra.Command {
	var o linuxdev.Options
	var f deviceReconFlags

	cmd := &cobra.Command{
		Use:   "ssh <user@host> [command]",
		Short: "Recon a phone booted into a Linux distribution (postmarketOS, Mobian, …) over ssh",
		Long: `Reconnaissance over ssh against a phone running a Linux distribution.

A booted userspace answers what no bootloader will: which distribution and kernel
are installed, the device package's own idea of which device this is, the SoC as
sysfs reports it, and the whole partition table by name. With root on the device
(--read-partitions) it also hands over the partition bytes, which is otherwise an
EDL-only capability — the identity and boot-chain partitions are then run through
the same recognizers a firmware package's members go through.

Connections use Go's own ssh client: the agent and ~/.ssh keys first, a password
only if no key works, and host keys checked against known_hosts. Pass --ssh to
drive the host ssh binary instead, for a ~/.ssh/config alias or a ProxyJump.

` + sshPasswordHelp,
		Args: cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				return fmt.Errorf("no ssh target given (expected user@host)")
			}
			return runSSHRecon(args[0], o, f)
		},
	}

	cmd.PersistentFlags().StringVarP(&o.User, "user", "l", "", "login user (overrides any user@ in the target)")
	cmd.PersistentFlags().StringVarP(&o.Port, "port", "p", "", "ssh port (default 22)")
	cmd.PersistentFlags().StringVarP(&o.Identity, "identity", "i", "", "private key file (default: the agent, then ~/.ssh/id_*)")
	cmd.PersistentFlags().StringVar(&o.HostKeys, "host-keys", linuxdev.HostKeysStrict,
		"host-key policy: strict, accept-new (record an unknown key), off (verify nothing)")
	cmd.PersistentFlags().StringVar(&o.KnownHosts, "known-hosts", "", "known_hosts file (default ~/.ssh/known_hosts)")
	cmd.PersistentFlags().StringVar(&o.Elevate, "elevate", "auto",
		"privilege helper for partition reads: auto, sudo, doas, none (a prompting sudo is given the login password, or "+linuxdev.PasswordEnv+")")
	cmd.PersistentFlags().StringVar(&o.SSHPath, "ssh", "",
		"use the host ssh binary instead of the built-in client — for a ~/.ssh/config alias, a ProxyJump or a smartcard (\"ssh\" resolves from PATH)")
	cmd.PersistentFlags().StringArrayVar(&o.Args, "ssh-opt", nil, "extra argument for --ssh, repeatable (e.g. --ssh-opt=-oProxyJump=bastion)")

	sub := newSSHReconCmd(&o, &f)
	cmd.AddCommand(sub)
	// The bare `ssh <target>` form runs recon, so the flags have to exist on
	// both; declared once on the subcommand and shared.
	cmd.Flags().AddFlagSet(sub.Flags())
	return cmd
}

func newSSHReconCmd(o *linuxdev.Options, f *deviceReconFlags) *cobra.Command {
	c := &cobra.Command{
		Use:   "recon <user@host>",
		Short: "collect what a booted Linux install says about the device, and derive from it",
		Long: `Collect what a booted Linux install says about the device, and derive from it.

` + sshPasswordHelp,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runSSHRecon(args[0], *o, *f)
		},
	}
	f.register(c)
	return c
}

func runSSHRecon(target string, o linuxdev.Options, f deviceReconFlags) error {
	// The distribution table comes from the catalog, so which files name the
	// device on which distribution is data the operator can extend.
	o.Distros = distro.New(activeCatalog().Distros())

	stop := spin("connecting to %s…", target)
	linuxdev.BeforePrompt = stop
	dev, err := linuxdev.Open(target, o)
	stop()
	if err != nil {
		return err
	}

	return runTransportRecon(dev, f, func() {
		printSSHSections(dev, activeCatalog(), library.Open(libraryDir()), f)
	})
}

// printSSHSections renders what a booted Linux install knows, in the order a
// reader wants it: what it is, what is installed on it, how it booted, what
// storage it has. The shape follows `fastboot recon` so the two read alike.
func printSSHSections(dev *linuxdev.Device, cat *catalog.Catalog, lib *library.Library, f deviceReconFlags) {
	r := dev.R
	redact := f.redact
	fmt.Printf("Linux Device: %s\n", r.Target)

	fmt.Println(cHdr("  Operating System:"))
	distroLine := r.OS.Describe()
	if r.Distro == nil && distroLine != "" {
		// Not a failure, but worth saying: everything device-side was still
		// collected, and only the distribution's own device definition is
		// unread. An entry in catalog/distros.yaml is what teaches it.
		distroLine += " — " + cWarn("no distro profile (add one to catalog/distros.yaml)")
	}
	printField("Distribution", distroLine)
	if r.Kernel.Release != "" {
		printField("Kernel", strings.TrimSpace(r.Kernel.Release+" ("+r.Kernel.Machine+")"))
	}
	printField("Hostname", mask(redact, r.Hostname))
	access := r.DescribeLogin()
	switch {
	case r.UID == 0:
		access += " — " + cGood("root: partitions readable")
	case r.ElevateOK != "":
		access += " — " + cGood("passwordless "+r.ElevateOK+": partitions readable")
	case r.Elevate == "sudo":
		// Usable: the password goes to sudo's stdin over the same channel.
		access += " — " + cGood("sudo (asks for a password)")
	case r.Elevate != "":
		access += " — " + cWarn(r.Elevate+" wants a password it will only read from a terminal: no partition reads")
	default:
		access += " — " + cWarn("unprivileged: no partition reads")
	}
	printField("Access", access)
	switch r.ShellRecon.BootMedium() {
	case "removable":
		printField("Boot Medium", cGood(fmt.Sprintf("removable (%s) — the internal OS is intact; its firmware is recoverable from disk", r.RootSource)))
	case "ram":
		printField("Boot Medium", cGood("RAM/initramfs — the internal OS is intact; its firmware is recoverable from disk"))
	case "internal":
		printField("Boot Medium", fmt.Sprintf("internal (%s) — this install replaced the original OS", r.RootSource))
	}

	// Nothing identifies the device on a host that is not one (a laptop reached
	// by the same command, a device whose install ships no deviceinfo), so the
	// section appears only when something filled it.
	codename := r.Codename()
	if codename != "" || r.DTModel != "" || len(r.SoCTokens()) > 0 || len(r.DeviceInfo) > 0 {
		fmt.Println("\n" + cHdr("  Device:"))
		if raw := r.DeviceInfo["codename"]; raw != "" && raw != codename {
			// The definition spells it "<vendor>-<codename>"; show both, since
			// the catalog is keyed by the second half and the package by the first.
			printField("Codename", fmt.Sprintf("%s (declared %s)", codename, raw))
		} else {
			printField("Codename", codename)
		}
		printField("Name", r.Claim.Name)
		printField("Manufacturer", r.Claim.Manufacturer)
		if r.Claim.From != "" {
			printField("Claimed By", r.Claim.From)
		}
		if soc := r.SoCTokens(); len(soc) > 0 {
			printField("SoC (as booted)", strings.Join(soc, ", "))
		}
		printField("Device Tree", r.DTModel)
		if r.Claim.Chassis != "" {
			printField("Chassis", strings.TrimSpace(r.Claim.Chassis+" "+r.Claim.Year))
		}
		if pct := r.BatteryPercent(); pct >= 0 {
			printField("Battery", fmt.Sprintf("%d%%", pct))
		}
	}

	// What this install would need for the recon to see more of it. A missing
	// device package is the difference between a codename and a guess, and
	// saying which package is the difference between a warning and a fix.
	if len(r.Missing) > 0 {
		fmt.Println("\n" + cHdr("  Install Gaps:"))
		for _, m := range r.Missing {
			fmt.Println("    " + cWarn("[!] "+m.What))
			if m.Why != "" {
				fmt.Println("        " + m.Why)
			}
			if m.Fix != "" {
				fmt.Println("        fix: " + m.Fix)
			}
		}
	}

	printCatalogSections(codename, cat, lib)
	printBootStateSection(r.Slot(), r.LockState(), r.Cmdline, r.ABDevice(), redact)

	if len(r.Partitions) > 0 {
		fmt.Println("\n" + cHdr("  Storage & Partitions:"))
		if r.Storage != "" {
			printField("Storage", r.Storage+" (inferred from block devices)")
		}
		for _, d := range r.Disks {
			printField("Disk "+d.Name, formatSizeKB(d.SizeBytes/1024))
		}
		printPartitionSections(dev, f.readCap)
	}

	if !f.readParts && r.CanReadPartitions() && len(r.Partitions) > 0 {
		fmt.Println("\n" + cHdr("  Next Steps:"))
		fmt.Println("    • Read the identity and boot-chain partitions:")
		fmt.Printf("        unbrick ssh recon %s --read-partitions\n", r.Target)
		fmt.Println("      CID, signing identity, AVB key and anti-rollback state all live in")
		fmt.Println("      partition content, which this device will hand over without EDL.")
	}
	if f.raw {
		printShellRaw(r.Sections, redact)
	}
}

// printCatalogSections is the catalog and library cross-reference: whether this
// is a device the tool can build a blankflash for, and whether it already holds
// firmware for it. The same question `fastboot recon` answers, asked of a
// codename that came from a running system rather than the bootloader.
func printCatalogSections(codename string, cat *catalog.Catalog, lib *library.Library) {
	if codename == "" {
		return
	}
	fmt.Println("\n" + cHdr("  Catalog & Library:"))
	dev, ok := cat.Device(codename)
	if !ok || dev == nil {
		printField("Catalog Match", cWarn("no catalog entry for "+codename))
		return
	}
	desc := fmt.Sprintf("%s — %s (%s", dev.Codename, dev.Name, dev.Vendor)
	if dev.CPUName != "" {
		desc += ", cpu_name " + dev.CPUName
	}
	printField("Catalog Match", desc+")")
	if soc, _ := cat.SoCByCPUName(dev.Vendor, dev.CPUName); soc != "" {
		printField("Catalog SoC", soc)
	}
	if len(dev.JTAGIDs) > 0 {
		printField("JTAG IDs", strings.Join(dev.JTAGIDs, ", "))
	}
	if builds := lib.StockBuilds(dev.Vendor, dev.Codename); len(builds) > 0 {
		names := make([]string, 0, len(builds))
		for _, b := range builds {
			names = append(names, b.Build)
		}
		sort.Strings(names)
		printField("Stored Builds", fmt.Sprintf("%d: %s", len(names), strings.Join(names, ", ")))
	}
	if loaders := lib.CandidateLoaders(dev); len(loaders) > 0 {
		printField("Candidate Loaders", fmt.Sprintf("%d in library", len(loaders)))
	}
}

// printBootStateSection shows how the device booted. On a phone whose userspace
// is chainloaded by the stock boot chain, the bootloader's own androidboot.*
// parameters survive into /proc/cmdline, which is the only place a booted
// system learns the slot and the lock state.
func printBootStateSection(slot, lock string, cmdline map[string]string, ab, redact bool) {
	if slot == "" && lock == "" && cmdline["androidboot.serialno"] == "" && !ab {
		return
	}
	fmt.Println("\n" + cHdr("  Boot State:"))
	if slot != "" {
		printField("Slot", "_"+slot)
	}
	if lock != "" {
		state := cWarn(strings.ToUpper(lock))
		if lock == "unlocked" {
			state = cGood("UNLOCKED")
		}
		if vbs := cmdline["androidboot.verifiedbootstate"]; vbs != "" {
			state += " (verifiedbootstate: " + vbs + ")"
		}
		printField("Lock Status", state)
	}
	printField("Serial", mask(redact, cmdline["androidboot.serialno"]))
	printField("Bootloader", cmdline["androidboot.bootloader"])
	printField("Baseband", cmdline["androidboot.baseband"])
	printField("Boot Reason", firstNonEmpty(cmdline["androidboot.bootreason"], cmdline["bootreason"]))
	printField("A/B Device", yesno(ab))
}

// printShellRaw dumps every collected section unparsed, for the facts the
// report has no line for yet.
func printShellRaw(sections map[string]string, redact bool) {
	fmt.Println("\n" + cHdr("  Raw Device Output:"))
	for _, name := range sortedKeys(sections) {
		body := strings.TrimSpace(sections[name])
		if body == "" {
			continue
		}
		fmt.Printf("    %s:\n", name)
		for _, line := range strings.Split(body, "\n") {
			if redact && sensitiveLine(line) {
				k, v, _ := strings.Cut(line, ":")
				line = k + ": " + mask(true, strings.TrimSpace(v))
			}
			fmt.Println("      " + line)
		}
	}
}

// sensitiveLine reports whether a raw line carries a per-device identifier worth
// masking under --redact.
func sensitiveLine(line string) bool {
	low := strings.ToLower(line)
	for _, k := range []string{"serial", "imei", "meid", "uid", "iccid", "androidboot.serialno"} {
		if strings.HasPrefix(strings.TrimSpace(low), k) {
			return true
		}
	}
	return false
}
