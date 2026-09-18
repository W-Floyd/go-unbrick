package fastboot

import (
	"bytes"
	"context"
	"errors"
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

// Client executes fastboot commands via host binary found in PATH.
type Client struct {
	binPath string
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

// run runs a fastboot command with a timeout.
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

// GetVar queries a single bootloader variable.
func (c *Client) GetVar(serial, varName string) (string, error) {
	args := []string{}
	if serial != "" {
		args = append(args, "-s", serial)
	}
	args = append(args, "getvar", varName)

	out, err := c.run(5*time.Second, args...)
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

// GetVarAll queries all device properties and returns a parsed DeviceRecon struct.
func (c *Client) GetVarAll(serial string) (*DeviceRecon, error) {
	args := []string{}
	if serial != "" {
		args = append(args, "-s", serial)
	}
	args = append(args, "getvar", "all")

	out, err := c.run(10*time.Second, args...)
	if err != nil && !strings.Contains(out, "(bootloader)") && !strings.Contains(out, "product:") {
		return nil, err
	}

	recon := ParseGetVarOutput(out)
	targetSerial := serial
	if targetSerial != "" {
		recon.Serial = targetSerial
	} else if len(recon.Serial) == 0 {
		if devs, err := c.Devices(); err == nil && len(devs) > 0 {
			recon.Serial = devs[0].Serial
			targetSerial = devs[0].Serial
		}
	}

	// Safely probe OEM hardware sensor capabilities if supported
	if hwOut, err := c.run(2*time.Second, appendSerial(targetSerial, "oem", "hw")...); err == nil {
		recon.HardwareFeatures = ParseOEMHwOutput(hwOut)
	}

	// Safely probe OEM security version registers / anti-rollback indices if supported
	if svOut, err := c.run(2*time.Second, appendSerial(targetSerial, "oem", "read_sv")...); err == nil {
		recon.SecurityVersions = ParseOEMReadSVOutput(svOut)
	}

	// Safely probe OEM partition layout and detect dynamic slot allocation if supported
	if partOut, err := c.run(3*time.Second, appendSerial(targetSerial, "oem", "partition")...); err == nil {
		parts, unpop, unpopList := ParseOEMPartitionOutput(partOut)
		recon.LivePartitions = parts
		recon.UnpopulatedSlotB = unpop
		recon.UnpopulatedParts = unpopList

		// The dynamic/empty verdicts above are read off offsets and sizes in one
		// text dump. Confirm exactly those against the bootloader's own answers —
		// a few dozen round trips, not the whole table, so recon stays quick.
		var suspect []string
		for _, p := range parts {
			if p.IsSuper || p.SizeKB == 0 {
				suspect = append(suspect, p.Name)
			}
		}
		if len(suspect) > 0 {
			recon.PartitionFacts = c.ProbePartitions(targetSerial, suspect)
		}
	}

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
// omits these variables, but they are served by name, so the only cost is one
// round trip each (~13ms). Anything the device declines is left zero rather than
// guessed at.
func (c *Client) ProbePartitions(serial string, names []string) map[string]PartitionFacts {
	out := make(map[string]PartitionFacts, len(names))
	for _, name := range names {
		f := PartitionFacts{}
		if v, err := c.GetVar(serial, "partition-type:"+name); err == nil {
			f.Type = strings.TrimSpace(v)
		}
		if v, err := c.GetVar(serial, "is-logical:"+name); err == nil {
			f.IsLogical = strings.EqualFold(strings.TrimSpace(v), "yes")
		}
		if v, err := c.GetVar(serial, "has-slot:"+strings.TrimSuffix(strings.TrimSuffix(name, "_a"), "_b")); err == nil {
			f.HasSlot = strings.EqualFold(strings.TrimSpace(v), "yes")
		}
		if v, err := c.GetVar(serial, "partition-size:"+name); err == nil {
			f.SizeBytes = parseSize(strings.TrimSpace(v))
		}
		out[name] = f
	}
	return out
}

// Motorola's ABL carries `oem partition` subcommands its own `help` does not
// list: dump, erase, md5, sha256, moto-dump and moto-pull (plus ramdump-pull).
// They are all `oem partition <sub> ...`, not top-level `oem <sub>` — that
// namespace matters, since `oem moto-dump` is rejected as "not a supported oem
// command" while `oem partition moto-dump <part>` reaches the handler. Across a
// locked (oem_locked) and an unlocked (flashing_unlocked) fogona (U1TF34.100-35-14)
// they fall into three distinct gates:
//
//	md5 / sha256 / moto-dump <part> -> "Command restricted!" (factory/eng gate)
//	dump <part> <off> <sz>          -> "Latest Motorola fastboot required, ..."
//	moto-pull <x> / ramdump-pull <x> -> "Invalid partition!" (ungated; arg check)
//
// The factory gate is NOT the OEM bootloader lock: both units refuse identically,
// and ABL reads an internal factory/engineering-mode flag the lock state never
// touches (MotoBootModule.efi .data+0xeb10c, read by the permission predicate;
// `factory-modes` is "disabled" on both). Unlocking does not lift it — the
// remaining routes are a factory/BP-tools cable or the hardware test point.
//
// The dump message is a client gate: dump moves bulk data over a pull channel
// AOSP fastboot does not speak, so it fails even unlocked. Reported apart from the
// factory gate so an operator is not sent chasing the wrong obstacle.
//
// moto-pull / ramdump-pull are past both gates but reject every GPT label with
// "Invalid partition!", so their target namespace is not GPT partitions — most
// likely ramdump region ids valid only after a crash (their strings sit in the
// module's ramdump cluster, beside get_ramoops_mem and "disable full ramdump").
// Even given a valid target the pull would hit the same client gate as dump.
// None of the six is wired as a callable command here; documented, not exposed.
var (
	ErrOEMRestricted         = errors.New("bootloader refused the command as restricted (factory/engineering-mode gate, not the OEM lock)")
	ErrNeedsMotorolaFastboot = errors.New("command requires Motorola's own fastboot client")
)

// PartitionDigest is one partition hash as the bootloader computed it.
type PartitionDigest struct {
	Partition string
	Algorithm string // md5 or sha256
	Digest    string // lowercase hex
	Range     string // the offset/size arguments sent, empty for a whole-partition hash
}

// OEMPartitionHash asks the bootloader to hash a partition in place. offset and
// size are passed through verbatim when non-empty; their units are whatever the
// bootloader means by them, which the partition listing gives in KB.
func (c *Client) OEMPartitionHash(serial, algo, partition, offset, size string) (*PartitionDigest, error) {
	args := []string{"oem", "partition", algo, partition}
	if offset != "" {
		args = append(args, offset)
		if size != "" {
			args = append(args, size)
		}
	}
	out, runErr := c.run(30*time.Second, appendSerial(serial, args...)...)
	digest, err := ParseOEMPartitionHashOutput(out, algo)
	if err != nil {
		return nil, err
	}
	if digest == "" {
		if runErr != nil {
			return nil, runErr
		}
		return nil, fmt.Errorf("no %s digest in bootloader output: %s", algo, strings.TrimSpace(out))
	}
	d := &PartitionDigest{Partition: partition, Algorithm: algo, Digest: digest}
	if offset != "" {
		d.Range = offset
		if size != "" {
			d.Range += "+" + size
		}
	}
	return d, nil
}

// ParseOEMPartitionHashOutput pulls the digest out of an `oem partition
// md5|sha256` reply, or reports which gate refused it. The digest is matched by
// shape rather than by label, since the reply's wording is not documented and
// differs between bootloader generations.
func ParseOEMPartitionHashOutput(text, algo string) (string, error) {
	want := 64
	if strings.EqualFold(algo, "md5") {
		want = 32
	}
	for _, line := range strings.Split(text, "\n") {
		l := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), "(bootloader)"))
		switch {
		case strings.Contains(l, "Command restricted"):
			return "", ErrOEMRestricted
		case strings.Contains(l, "Latest Motorola fastboot required"):
			return "", ErrNeedsMotorolaFastboot
		}
		for _, tok := range strings.FieldsFunc(l, func(r rune) bool { return r == ' ' || r == ':' || r == '\t' || r == '=' }) {
			tok = strings.ToLower(strings.TrimSpace(tok))
			if len(tok) == want && strings.Trim(tok, "0123456789abcdef") == "" {
				return tok, nil
			}
		}
	}
	return "", nil
}

// OEMHw queries hardware sensor and module capabilities ('fastboot oem hw').
func (c *Client) OEMHw(serial string) (*OEMHardwareInfo, error) {
	out, err := c.run(5*time.Second, appendSerial(serial, "oem", "hw")...)
	if err != nil {
		return nil, err
	}
	return ParseOEMHwOutput(out), nil
}

// OEMReadSV queries security version registers / anti-rollback indices ('fastboot oem read_sv').
func (c *Client) OEMReadSV(serial string) (*SecurityVersions, error) {
	out, err := c.run(5*time.Second, appendSerial(serial, "oem", "read_sv")...)
	if err != nil {
		return nil, err
	}
	return ParseOEMReadSVOutput(out), nil
}

// OEMPartitions queries live partition geometry from UFS/eMMC ('fastboot oem partition').
func (c *Client) OEMPartitions(serial string) ([]PartitionDetail, bool, []string, error) {
	out, err := c.run(5*time.Second, appendSerial(serial, "oem", "partition")...)
	if err != nil {
		return nil, false, nil, err
	}
	parts, unpop, unpopList := ParseOEMPartitionOutput(out)
	return parts, unpop, unpopList, nil
}

// SetActiveSlot switches the active A/B slot ('a' or 'b').
func (c *Client) SetActiveSlot(serial, slot string) error {
	slotClean := strings.TrimPrefix(strings.ToLower(strings.TrimSpace(slot)), "_")
	if slotClean != "a" && slotClean != "b" {
		return fmt.Errorf("invalid slot %q (must be 'a' or 'b')", slot)
	}

	args := []string{}
	if serial != "" {
		args = append(args, "-s", serial)
	}
	args = append(args, fmt.Sprintf("--set-active=%s", slotClean))

	_, err := c.run(10*time.Second, args...)
	return err
}

// Flash writes file to the named partition. A locked bootloader rejects this
// for non-standard partitions; the caller is expected to gate on unlock state.
func (c *Client) Flash(serial, partition, file string) error {
	args := appendSerial(serial, "flash", partition, file)
	_, err := c.run(120*time.Second, args...)
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
		args := []string{}
		if serial != "" {
			args = append(args, "-s", serial)
		}
		args = append(args, cmdArgs...)

		out, err := c.run(5*time.Second, args...)
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

// GetUnlockData queries the Motorola OEM unlock data token string.
func (c *Client) GetUnlockData(serial string) (string, error) {
	args := []string{}
	if serial != "" {
		args = append(args, "-s", serial)
	}
	args = append(args, "oem", "get_unlock_data")

	out, err := c.run(5*time.Second, args...)
	if err != nil && !strings.Contains(out, "(bootloader)") {
		return "", err
	}

	var tokenParts []string
	for _, line := range strings.Split(out, "\n") {
		trimmed := strings.TrimSpace(line)
		trimmed = strings.TrimPrefix(trimmed, "(bootloader)")
		trimmed = strings.TrimSpace(trimmed)
		if len(trimmed) > 16 && !strings.Contains(trimmed, " ") {
			tokenParts = append(tokenParts, trimmed)
		}
	}

	if len(tokenParts) == 0 {
		return strings.TrimSpace(out), nil
	}
	return strings.Join(tokenParts, ""), nil
}

