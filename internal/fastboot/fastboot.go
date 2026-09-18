package fastboot

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// Device represents one connected fastboot device.
type Device struct {
	Serial string
	State  string // e.g. "fastboot"
}

// Client executes fastboot commands via host binary found in PATH. An optional
// vendor Profile (see profile.go) stacks middleware, probes, and capability
// qualifiers on top; it is nil-safe and defaults to Generic.
type Client struct {
	binPath string
	profile Profile
	prog    ProgressSink
}

// ProgressSink receives paced-recon progress so the command layer can draw a
// bar without this package importing a UI library. Begin sets the (fixed) step
// total; Describe labels the step now running; Advance marks it complete. The
// label is set before the work and the count advances after it, so the bar
// tracks finished steps rather than jumping ahead. The total never grows once
// set — sub-steps (per-partition probes) relabel via Describe without advancing,
// so the bar only ever moves forward. See cmd_fastboot.
type ProgressSink interface {
	Begin(total int)
	Describe(label string)
	Advance()
}

// SetProgress installs a progress sink; nil disables progress reporting.
func (c *Client) SetProgress(s ProgressSink) { c.prog = s }

func (c *Client) beginProgress(total int) {
	if c.prog != nil {
		c.prog.Begin(total)
	}
}

// describeStep names the step about to run; advanceStep counts it once done.
func (c *Client) describeStep(label string) {
	if c.prog != nil {
		c.prog.Describe(label)
	}
}

func (c *Client) advanceStep() {
	if c.prog != nil {
		c.prog.Advance()
	}
}

// NewClient returns a Client using the host fastboot binary.
// If customPath is non-empty, it uses that; otherwise it resolves "fastboot" from PATH.
func NewClient(customPath string) (*Client, error) {
	if customPath != "" {
		return &Client{binPath: customPath}, nil
	}
	p, err := exec.LookPath("fastboot")
	if err != nil {
		return nil, fmt.Errorf("fastboot binary not found in PATH: %w\nInstall Android platform-tools or add fastboot to your PATH", err)
	}
	return &Client{binPath: p}, nil
}

// BinaryPath returns the path to the resolved fastboot binary.
func (c *Client) BinaryPath() string {
	return c.binPath
}

// run runs a fastboot command with a timeout. It is the base runner Middleware
// wraps; vendor code reaches it through Exec, not directly.
func (c *Client) run(timeout time.Duration, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, c.binPath, args...)
	var combined bytes.Buffer
	cmd.Stdout = &combined
	cmd.Stderr = &combined

	err := cmd.Run()
	output := combined.String()

	if ctx.Err() == context.DeadlineExceeded {
		return output, fmt.Errorf("fastboot command timed out after %v: %v", timeout, args)
	}
	if err != nil {
		return output, fmt.Errorf("fastboot %s failed: %w (output: %s)", strings.Join(args, " "), err, strings.TrimSpace(output))
	}
	return output, nil
}

// Devices queries connected devices running in fastboot mode.
func (c *Client) Devices() ([]Device, error) {
	out, err := c.run(5*time.Second, "devices")
	if err != nil {
		return nil, err
	}

	var devices []Device
	lines := strings.Split(out, "\n")
	for _, l := range lines {
		trimmed := strings.TrimSpace(l)
		if trimmed == "" {
			continue
		}
		fields := strings.Fields(trimmed)
		if len(fields) >= 2 {
			devices = append(devices, Device{
				Serial: fields[0],
				State:  fields[1],
			})
		} else if len(fields) == 1 {
			devices = append(devices, Device{
				Serial: fields[0],
				State:  "fastboot",
			})
		}
	}
	return devices, nil
}

// GetVar queries a single bootloader variable (through profile middleware).
func (c *Client) GetVar(serial, varName string) (string, error) {
	out, err := c.Exec(serial, 5*time.Second, "getvar", varName)
	if err != nil {
		return "", err
	}

	// Parse "<varName>: <value>"
	for _, line := range strings.Split(out, "\n") {
		trimmed := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), "(bootloader)"))
		// Split after the variable's own name, not at the first colon: names like
		// "partition-type:super" contain one, and splitting naively hands back
		// "super: raw" instead of "raw".
		if strings.HasPrefix(strings.ToLower(trimmed), strings.ToLower(varName)+":") {
			return strings.TrimSpace(trimmed[len(varName)+1:]), nil
		}
	}
	return "", nil
}

// GetVarAll queries all device properties and returns a parsed DeviceRecon. It
// runs only the neutral `getvar all`; vendor probes are applied separately by
// RunProbes once a Profile is installed.
func (c *Client) GetVarAll(serial string) (*DeviceRecon, error) {
	out, err := c.Exec(serial, 10*time.Second, "getvar", "all")
	if err != nil && !strings.Contains(out, "(bootloader)") && !strings.Contains(out, "product:") {
		return nil, err
	}

	recon := ParseGetVarOutput(out)
	if serial != "" {
		recon.Serial = serial
	} else if len(recon.Serial) == 0 {
		if devs, err := c.Devices(); err == nil && len(devs) > 0 {
			recon.Serial = devs[0].Serial
		}
	}

	// Vendor-specific probes (OEM commands, partition geometry, CID provisioning)
	// are not run here — they live in the installed Profile's recon probes and are
	// applied by RunProbes, so this stays a neutral `getvar all`.
	return recon, nil
}

func appendSerial(serial string, args ...string) []string {
	if serial != "" {
		return append([]string{"-s", serial}, args...)
	}
	return args
}

// InUserspace reports whether fastboot is being served by userspace fastbootd
// (recovery) rather than by the bootloader itself. The two are different
// programs with different command sets: every `oem` command this tool uses is
// ABL's, while flashing a logical partition is only possible in fastbootd.
//
// A device that does not answer the variable at all is treated as the
// bootloader, which is what every pre-dynamic-partitions device is.
func (c *Client) InUserspace(serial string) bool {
	v, err := c.GetVar(serial, "is-userspace")
	if err != nil {
		return false
	}
	v = strings.TrimSpace(v)
	return strings.EqualFold(v, "yes") || strings.EqualFold(v, "true")
}

// PartitionFacts is what the bootloader will answer about one partition by
// name. None of it appears in `getvar all`, and all of it answers on a locked
// device.
type PartitionFacts struct {
	Type      string // raw, or a filesystem when asked of userspace fastbootd
	IsLogical bool   // lives inside super — the bootloader's own answer
	HasSlot   bool   // partition is A/B
	SizeBytes uint64
}

// ProbePartitions asks the bootloader about each named partition. `getvar all`
// omits these variables, but they are served by name. Each is a separate round
// trip, and a pacing profile may space them (≥500ms on Motorola), so it costs
// 4 paced calls per name — prefer ProbePartitionState, or a tight name list,
// when the size/logical facts suffice. Declined vars are left zero, not guessed.
func (c *Client) ProbePartitions(serial string, names []string) map[string]PartitionFacts {
	return c.probePartitions(serial, names, false)
}

// ProbePartitionState is the cheap variant: it fetches only is-logical and
// partition-size — the two facts the empty-slot cross-check needs — halving the
// paced round trips per partition versus ProbePartitions.
func (c *Client) ProbePartitionState(serial string, names []string) map[string]PartitionFacts {
	return c.probePartitions(serial, names, true)
}

func (c *Client) probePartitions(serial string, names []string, lean bool) map[string]PartitionFacts {
	out := make(map[string]PartitionFacts, len(names))
	// These per-partition round trips are counted into the bar total up front by
	// the profile's ReconPlanner, so each one both relabels and advances the bar
	// (steady forward motion, no mid-run denominator growth).
	for i, name := range names {
		c.describeStep(fmt.Sprintf("checking partition %d/%d: %s", i+1, len(names), name))
		f := PartitionFacts{}
		if !lean {
			if v, err := c.GetVar(serial, "partition-type:"+name); err == nil {
				f.Type = strings.TrimSpace(v)
			}
		}
		if v, err := c.GetVar(serial, "is-logical:"+name); err == nil {
			f.IsLogical = strings.EqualFold(strings.TrimSpace(v), "yes")
		}
		if !lean {
			if v, err := c.GetVar(serial, "has-slot:"+strings.TrimSuffix(strings.TrimSuffix(name, "_a"), "_b")); err == nil {
				f.HasSlot = strings.EqualFold(strings.TrimSpace(v), "yes")
			}
		}
		if v, err := c.GetVar(serial, "partition-size:"+name); err == nil {
			f.SizeBytes = parseSize(strings.TrimSpace(v))
		}
		out[name] = f
		c.advanceStep()
	}
	return out
}

// SetActiveSlot switches the active A/B slot ('a' or 'b').
func (c *Client) SetActiveSlot(serial, slot string) error {
	slotClean := strings.TrimPrefix(strings.ToLower(strings.TrimSpace(slot)), "_")
	if slotClean != "a" && slotClean != "b" {
		return fmt.Errorf("invalid slot %q (must be 'a' or 'b')", slot)
	}
	_, err := c.Exec(serial, 10*time.Second, fmt.Sprintf("--set-active=%s", slotClean))
	return err
}

// Flash writes file to the named partition. A locked bootloader rejects this
// for non-standard partitions; the caller is expected to gate on unlock state.
func (c *Client) Flash(serial, partition, file string) error {
	_, err := c.Exec(serial, 120*time.Second, "flash", partition, file)
	return err
}

// RebootEDL instructs the bootloader into Qualcomm Emergency Download (9008)
// mode, using the commands the caller's vendor driver supplies — there is no
// common one, and firing every OEM's command at a bootloader that did not ask
// for it is noise at best. An empty list means no known route, which is a
// finding rather than a reason to start guessing.
func (c *Client) RebootEDL(serial string, commands [][]string) error {
	if len(commands) == 0 {
		return fmt.Errorf("no EDL entry route is known for this device")
	}

	var attempts []string
	for _, cmdArgs := range commands {
		out, err := c.Exec(serial, 5*time.Second, cmdArgs...)
		if err == nil {
			return nil
		}
		why := firstDeviceMessage(out)
		if why == "" {
			why = "no reply"
		}
		attempts = append(attempts, fmt.Sprintf("  %-22s %s", "fastboot "+strings.Join(cmdArgs, " "), why))
		if strings.Contains(strings.ToLower(why), "restricted") {
			return fmt.Errorf("the bootloader refused EDL entry as restricted (factory/engineering-mode gate, not the OEM lock — unlocking will not lift it):\n%s\nThe hardware test point is the remaining route.", strings.Join(attempts, "\n"))
		}
	}
	return fmt.Errorf("no EDL entry command was accepted:\n%s\nThe hardware test point or the key combination is the remaining route.",
		strings.Join(attempts, "\n"))
}

// firstDeviceMessage picks the most informative line out of a failed fastboot
// run: what the bootloader said, or failing that what the host tool said.
func firstDeviceMessage(out string) string {
	var hostSays string
	for _, line := range strings.Split(out, "\n") {
		l := strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(l, "(bootloader)"):
			if msg := strings.TrimSpace(strings.TrimPrefix(l, "(bootloader)")); msg != "" {
				return msg
			}
		case strings.HasPrefix(l, "fastboot:") && hostSays == "":
			hostSays = l
		}
	}
	return hostSays
}
