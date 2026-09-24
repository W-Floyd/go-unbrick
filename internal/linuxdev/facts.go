package linuxdev

// The booted device as a source of facts. A running Linux userspace is a
// different witness from the bootloader, not a better one: it knows what is
// installed and what the silicon says about itself, but everything it reports
// passes through a mutable filesystem and a kernel command line the
// distribution may have replaced. So its derivations are Derived where the
// bootloader's equivalents are Attested — a disagreement surfaces with the
// fastboot or package value winning the display, which is the right default.
//
// The exceptions are the facts about the install itself (which distribution,
// which kernel): there is no more authoritative source for those than the
// system answering the question.
//
// What any shell-reachable route derives — slot, lock state, SoC, A/B, the
// device tree's codename — is declared once in internal/transport and
// registered here over this route's own source key.

import (
	"go-unbrick/internal/facts"
	"go-unbrick/internal/transport"
)

// SourceLinux is one collected ssh recon. It costs a round trip to obtain,
// which the caller has already paid by the time it is in the Bag; the rules
// below only read the struct, so they price as the field reads they are.
var SourceLinux = facts.Key[*Recon]("source:device.linux",
	facts.Fmt(func(r *Recon) string { return "ssh " + r.Target + " (" + r.OS.Describe() + ")" }))

// Facts about the installed system, which only a booted device can answer.
// They are their own facts rather than variants of the Android build facts:
// postmarketOS is not a build of the OEM firmware, and folding the two would
// manufacture a disagreement between two correct answers.
var (
	// DeviceOS is the distribution installed on the device, as it names itself.
	DeviceOS = facts.Key[string]("device_os")
	// KernelRelease is uname -r: which kernel is actually running, mainline or
	// the OEM's downstream tree.
	KernelRelease = facts.Key[string]("kernel_release")
)

// FactProviders returns the derivations over a booted Linux device.
func FactProviders() []facts.Provider {
	shell := transport.ShellProviders("ssh", SourceLinux.Name(),
		func(b *facts.Bag) (*transport.ShellRecon, bool) {
			r, ok := facts.Get(b, SourceLinux)
			if !ok || r == nil {
				return nil, false
			}
			return r.ShellRecon, true
		}, facts.Derived)

	return append(shell,
		fromLinux(DeviceOS, facts.Attested, "/etc/os-release",
			func(r *Recon) (string, bool) {
				s := r.OS.Describe()
				return s, s != ""
			}),
		fromLinux(KernelRelease, facts.Attested, "uname -r",
			func(r *Recon) (string, bool) { return r.Kernel.Release, r.Kernel.Release != "" }),

		// The distribution's device package names the device by the OEM's own
		// codename, which is what makes a pmOS install resolvable against the
		// catalog at all. Derived: it is the packager's label, not the device's
		// — and the device tree's own answer is a separate provider, so the two
		// corroborate or disagree on the record.
		fromLinux(facts.Codename, facts.Derived, "deviceinfo codename",
			func(r *Recon) (string, bool) {
				c := r.DeviceInfo["codename"]
				if c == "" {
					return "", false
				}
				return r.Codename(), true
			}),
	)
}

// fromLinux is a rule reading one field of the collected recon.
func fromLinux[T any](out facts.Fact[T], level facts.Level, source string,
	fn func(*Recon) (T, bool)) facts.Rule {
	return facts.Rule{
		Out: out.Name(), In: []string{SourceLinux.Name()}, Price: 1, Level: level,
		Fn: func(b *facts.Bag) (bool, error) {
			r, ok := facts.Get(b, SourceLinux)
			if !ok || r == nil {
				return false, nil
			}
			v, ok := fn(r)
			if !ok {
				return false, nil
			}
			facts.Set(b, out, v, facts.Provenance{Source: source, Authority: level})
			return true, nil
		},
	}
}
