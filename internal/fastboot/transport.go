package fastboot

// The bootloader as a recon transport.
//
// It lists the partition table and refuses to read any of it, which is not an
// oversight in this adapter: `fastboot` has no read verb at all. The seam
// exists partly to say that out loud — a recon that wants partition *content*
// off this device has to reach it another way (boot it into Linux or Android,
// or go in over EDL), and the command layer can tell the operator so because
// the capability is simply absent here rather than failing at the last moment.

import (
	"sort"

	"github.com/W-Floyd/go-unbrick/internal/facts"
	"github.com/W-Floyd/go-unbrick/internal/transport"
)

// Transport is a device in fastboot mode, already reconned.
type Transport struct {
	C *Client
	R *DeviceRecon
}

var (
	_ transport.Transport       = (*Transport)(nil)
	_ transport.PartitionLister = (*Transport)(nil)
)

// NewTransport wraps a collected recon as a transport.
func NewTransport(c *Client, r *DeviceRecon) *Transport { return &Transport{C: c, R: r} }

func (t *Transport) Name() string { return transport.Fastboot }

func (t *Transport) Describe() string {
	if t.R.Serial != "" {
		return "fastboot " + t.R.Serial
	}
	return "fastboot device"
}

// Close is a no-op: the fastboot client holds no connection, only a path to a
// binary it invokes per command.
func (t *Transport) Close() error { return nil }

// Sources puts the collected recon in the Bag — the one source this route
// yields, from which the neutral and vendor rules derive everything the report
// shows.
func (t *Transport) Sources(b *facts.Bag) []facts.Finding {
	facts.Set(b, SourceRecon, t.R,
		facts.Provenance{Source: "getvar all", Authority: facts.Attested})
	return nil
}

// Partitions is what `getvar all` said about the table: names and sizes, which
// is all the bootloader volunteers. The per-partition variables (is-logical,
// partition-type) cost a paced round trip each and are probed separately.
func (t *Transport) Partitions() []transport.Partition {
	out := make([]transport.Partition, 0, len(t.R.PartitionSizes))
	for name, size := range t.R.PartitionSizes {
		out = append(out, transport.Partition{Name: name, SizeBytes: size})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// Slot is the booted A/B slot, as the bootloader reports it.
func (t *Transport) Slot() string { return t.R.CurrentSlot }
