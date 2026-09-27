package imgfacts

// A file as a recon transport.
//
// A firmware package is not a device, and calling it one would be a stretch if
// the seam were about connections. It is not: a transport's whole obligation is
// to put what a thing says about itself into the Bag as source facts, and that
// is exactly what ingesting a package does.
//
// Naming it a route is what lets one recon hold two. Read the device by ssh,
// adb or fastboot, read the firmware it is supposed to be running from a file,
// and the disagreements — a CID that does not match the package, an
// anti-rollback index the device has moved past, a fingerprint from another
// build — fall out of the graph's ordinary same-fact comparison instead of a
// hand-written comparison per pair.

import (
	"path/filepath"

	"github.com/W-Floyd/go-unbrick/internal/facts"
	"github.com/W-Floyd/go-unbrick/internal/transport"
)

// File is a package, image or dump on disk, offered to the recognizers.
type File struct {
	Path string
	// Recognizers decides what the file and its members are. The caller passes
	// the full set (neutral plus every vendor's), the same one a device's
	// partition reads go through.
	Recognizers []facts.Recognizer
	Progress    Progress // optional
}

var _ transport.Transport = (*File)(nil)

func (f *File) Name() string { return transport.File }

func (f *File) Describe() string { return "file " + filepath.Base(f.Path) }

// Close is a no-op: ingestion reads what it needs and holds nothing open.
func (f *File) Close() error { return nil }

// Sources ingests the file and everything inside it. What it contains is
// discovered, not assumed: every member is offered to the recognizers, which
// decide what each one is from its content.
func (f *File) Sources(b *facts.Bag) []facts.Finding {
	rs := f.Recognizers
	if rs == nil {
		rs = Recognizers()
	}
	if err := Ingest(b, rs, f.Path, f.Progress); err != nil {
		return []facts.Finding{transport.Gap("reading "+filepath.Base(f.Path), err)}
	}
	return nil
}
