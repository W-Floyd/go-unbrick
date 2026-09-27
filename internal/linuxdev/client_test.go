package linuxdev

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/W-Floyd/go-unbrick/internal/distro"
	"github.com/W-Floyd/go-unbrick/internal/transport"
)

// fakeSSH is an ssh stand-in for the exec transport: it answers the connection
// check, ignores the multiplexing options, and runs the script on stdin through
// the local shell. It is what makes the wire format testable without a phone —
// the collection script really executes, its output really goes through Parse,
// and a partition read really round-trips over a pipe.
const fakeSSH = `#!/bin/sh
for a in "$@"; do
	case "$a" in
	-O) exit 0 ;;            # ssh -O exit: tearing down the master
	true) exit 0 ;;          # the connection check
	esac
done
exec /bin/sh -s
`

func newFakeClient(t *testing.T) *Client {
	t.Helper()
	dir := t.TempDir()
	bin := filepath.Join(dir, "fake-ssh")
	if err := os.WriteFile(bin, []byte(fakeSSH), 0o755); err != nil {
		t.Fatalf("writing fake ssh: %v", err)
	}
	c, err := NewClient("phone.local", Options{SSHPath: bin})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func TestNewClientRejectsEmptyTarget(t *testing.T) {
	if _, err := NewClient("  ", Options{SSHPath: "/bin/true"}); err == nil {
		t.Error("an empty target was accepted")
	}
}

// The collection script has to run under a POSIX shell: it is executed by
// whatever /bin/sh the device has, which on postmarketOS is busybox ash. This
// runs it for real and checks that every section marker came back, which is the
// part a syntax error or a bad quote would break.
func TestCollectScriptRunsAndSections(t *testing.T) {
	c := newFakeClient(t)
	out, err := c.Run(CommandTimeout, collectScript(distro.Builtin()))
	if err != nil {
		t.Fatalf("running the collection script: %v", err)
	}
	secs := transport.SplitSections(out)
	for _, want := range []string{"os-release", "uname", "whoami", "hostname", "elevate",
		"elevate-ok", "commands", "distro-files", "cmdline", "cpuinfo", "soc0",
		"dt-model", "dt-compatible", "partitions", "disks", "battery"} {
		if _, ok := secs[want]; !ok {
			t.Errorf("section %q missing from collection output", want)
		}
	}
	// The host is not a phone, so the device sections are empty — which is the
	// point: an absent /proc/device-tree or /dev/block/by-name must not stop the
	// script or swallow the sections after it.
	if secs["uname"] == "" {
		t.Error("uname section is empty; the script stopped early")
	}
}

// Collect parses what it gets and records the target, even where the device
// answers almost nothing.
func TestCollectOnANonPhone(t *testing.T) {
	c := newFakeClient(t)
	r, err := Collect(c)
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if r.Target != "phone.local" {
		t.Errorf("target = %q", r.Target)
	}
	if len(r.Sections) == 0 {
		t.Error("no sections collected")
	}
}

// A partition read is raw dd over the channel, which is 8-bit clean with no tty
// in the way; this checks that on the bytes a text channel would mangle.
func TestReadPartitionRoundTrip(t *testing.T) {
	c := newFakeClient(t)
	want := make([]byte, 200*1024)
	for i := range want {
		want[i] = byte(i * 7 % 251)
	}
	// The bytes a naive transfer breaks on: NUL, CR, LF, ^D, 0x1b, 0xff.
	copy(want, []byte{0x00, 0x0d, 0x0a, 0x04, 0x1b, 0xff})

	path := filepath.Join(t.TempDir(), "cid.img")
	if err := os.WriteFile(path, want, 0o644); err != nil {
		t.Fatalf("writing fixture: %v", err)
	}

	got, err := ReadPartition(c, transport.Partition{Name: "cid", Handle: path, SizeBytes: uint64(len(want))}, uint64(len(want)))
	if err != nil {
		t.Fatalf("ReadPartition: %v", err)
	}
	// dd reads in whole blocks, so the tail is block-padded; the content up to
	// the partition's size is what must match.
	if len(got) < len(want) || !bytes.Equal(got[:len(want)], want) {
		t.Errorf("read back %d bytes, want the %d written", len(got), len(want))
	}
}

func TestReadPartitionWithoutADeviceNode(t *testing.T) {
	c := newFakeClient(t)
	if _, err := ReadPartition(c, transport.Partition{Name: "cid"}, 4096); err == nil {
		t.Error("a table entry with no device node was read anyway")
	}
}

// A failed read must carry the device's own complaint rather than a guess: a
// denied read and a dropped connection are different problems, and reporting
// either as the other sends the operator after the wrong thing.
func TestReadPartitionFailureCarriesTheReason(t *testing.T) {
	c := newFakeClient(t)
	path := filepath.Join(t.TempDir(), "missing.img")
	_, err := ReadPartition(c, transport.Partition{Name: "cid", Handle: path, SizeBytes: 4096}, 4096)
	if err == nil {
		t.Fatal("reading a missing device node succeeded")
	}
	if !strings.Contains(err.Error(), "cid") || !strings.Contains(err.Error(), "No such file") {
		t.Errorf("error names neither the partition nor dd's reason: %v", err)
	}
}

// An empty read with no complaint is the shape a refused block-device open
// takes, and the one case where the message may point at privileges.
func TestReadPartitionEmptyPointsAtPrivileges(t *testing.T) {
	c := newFakeClient(t)
	empty := filepath.Join(t.TempDir(), "empty.img")
	if err := os.WriteFile(empty, nil, 0o644); err != nil {
		t.Fatalf("writing fixture: %v", err)
	}
	_, err := ReadPartition(c, transport.Partition{Name: "cid", Handle: empty, SizeBytes: 4096}, 4096)
	if err == nil || !strings.Contains(err.Error(), "root") {
		t.Errorf("error = %v, want one pointing at privileges", err)
	}
}

func TestShellQuote(t *testing.T) {
	// A device node whose name came from the device, quoted so the remote shell
	// cannot be talked into anything.
	if got := shellQuote("/dev/block/by-name/x; rm -rf /"); got != `'/dev/block/by-name/x; rm -rf /'` {
		t.Errorf("shellQuote = %s", got)
	}
	if got := shellQuote("it's"); got != `'it'\''s'` {
		t.Errorf("shellQuote of an embedded quote = %s", got)
	}
}
