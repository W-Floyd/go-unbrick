package imgfacts

import (
	"github.com/W-Floyd/go-unbrick/internal/facts"
	"github.com/W-Floyd/go-unbrick/internal/payload"
)

// ingestPayload offers every small partition of an OTA's payload.bin to the
// recognizers, as a flashable package's members would be: an OTA keeps inside
// payload.bin what other packages keep at top level (vbmeta, the signed boot
// stages), and what each one means is the recognizers' call. Reads are lazy,
// so over HTTP this costs only those partitions' compressed bytes.
func ingestPayload(b *facts.Bag, rs []facts.Recognizer, path, base string) {
	pl, closer, err := payload.OpenZip(path)
	if err != nil {
		return
	}
	defer closer.Close()
	for _, name := range pl.Partitions() {
		ra, size, err := pl.PartitionReaderAt(name)
		if err != nil || size > maxMemberRead {
			continue
		}
		data := make([]byte, size)
		if _, err := ra.ReadAt(data, 0); err != nil {
			continue
		}
		facts.Recognize(b, rs, facts.File{Name: name, Data: data, From: base + " payload " + name})
	}
}
