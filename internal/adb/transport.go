package adb

// The adb route as a recon transport: the property system, the partition table,
// and — with root — the partition bytes.

import (
	"github.com/W-Floyd/go-unbrick/internal/facts"
	"github.com/W-Floyd/go-unbrick/internal/transport"
)

// Device is a phone booted into Android, reached over adb.
type Device struct {
	C *Client
	R *Recon

	collectErr error
}

var (
	_ transport.Transport       = (*Device)(nil)
	_ transport.PartitionLister = (*Device)(nil)
	_ transport.PartitionReader = (*Device)(nil)
)

// Open connects to the adb server, selects a device and collects.
func Open(o Options) (*Device, error) {
	c, err := NewClient(o)
	if err != nil {
		return nil, err
	}
	r, cerr := Collect(c)
	if r == nil {
		return nil, cerr
	}
	return &Device{C: c, R: r, collectErr: cerr}, nil
}

func (d *Device) Name() string { return transport.ADB }

func (d *Device) Describe() string {
	desc := "adb " + d.R.Serial
	if fp := d.R.Fingerprint(); fp != "" {
		return desc + " (" + fp + ")"
	}
	return desc
}

func (d *Device) Close() error { return d.C.Close() }

func (d *Device) Sources(b *facts.Bag) []facts.Finding {
	facts.Set(b, SourceADB, d.R,
		facts.Provenance{Source: "adb " + d.R.Serial, Authority: facts.Attested})
	if d.collectErr != nil {
		return []facts.Finding{transport.Gap("collecting over adb", d.collectErr)}
	}
	return nil
}

func (d *Device) Partitions() []transport.Partition { return d.R.Partitions }

func (d *Device) Slot() string { return d.R.Slot() }

func (d *Device) ReadPartition(p transport.Partition, budget uint64) ([]byte, error) {
	return ReadPartition(d.C, p, budget)
}

// ReadCost prices one read on the fact graph's scale: base64 over the adb
// shell channel, which is USB-fast but pays a third of itself in encoding.
func (d *Device) ReadCost() int { return 60 }

// The provisioning side of the same connection: a shell, an installer, and the
// API level. Declared here so the compiler holds this route to what
// internal/provision needs, rather than finding out at the call site.
var _ interface {
	Serial() string
	Shell(cmd string) (string, error)
	InstallAPK(path string, reinstall, grantRuntime bool) error
	SDK() int
} = (*Device)(nil)

// Shell runs one command on the device.
func (d *Device) Shell(cmd string) (string, error) { return d.C.Shell(cmd) }

// SDK is the device's API level, 0 when unknown.
func (d *Device) SDK() int { return d.C.SDK() }

// Serial identifies the device.
func (d *Device) Serial() string { return d.R.Serial }

// InstallAPK pushes and installs a local APK.
func (d *Device) InstallAPK(path string, reinstall, grantRuntime bool) error {
	return InstallAPK(d.C, path, reinstall, grantRuntime)
}

// PrepareReads settles root before a run of reads, so a shell that cannot
// become root says so once rather than per partition.
func (d *Device) PrepareReads() error {
	if d.R.CanReadPartitions() {
		return nil
	}
	if d.R.Elevate == "su" {
		return errNoRoot("su is present but this shell could not become root with it — on Magisk, grant the shell root in the Magisk app")
	}
	return errNoRoot("the adb shell is not root and the device has no su: `adb root` works only on a userdebug/eng build, so reading partitions needs a rooted device, a boot into Linux (ssh), or EDL")
}

type errNoRoot string

func (e errNoRoot) Error() string { return string(e) }

// DeviceSerial is the unit's hardware serial, used only to recognise the same
// physical device across a session's routes; it is never stored.
func (d *Device) DeviceSerials() []string {
	return transport.NonEmpty(d.R.Serial, d.R.StorSerial)
}
