package imgfacts

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/W-Floyd/go-unbrick/internal/catalog"
	"github.com/W-Floyd/go-unbrick/internal/facts"
)

// BTFirmwareFile is one file of a Qualcomm BTFM firmware partition: a patch
// (<chip>btfw<NN>.tlv) or the build stamp beside it (.ver).
type BTFirmwareFile struct {
	Name  string
	Build string // first line of a .ver
}

var btFile = regexp.MustCompile(`^([a-z]+)btfw([0-9a-z]+)\.(tlv|ver)$`)

// btFirmwareRule summarizes which chips the partition ships firmware for. The
// HAL chooses among them from the chip's reported version, so a package alone
// cannot say which is fitted.
var btFirmwareRule = facts.Rule{
	Out: facts.BluetoothFirmware.Name(), In: []string{SourceBTFirmware.Name()}, Price: 1, Level: facts.Attested,
	Fn: func(b *facts.Bag) (bool, error) {
		type chip struct {
			vers  []string
			build string
		}
		chips := map[string]*chip{}
		for _, f := range facts.GetAll(b, SourceBTFirmware) {
			m := btFile.FindStringSubmatch(f.Name)
			if m == nil {
				continue
			}
			c := chips[m[1]]
			if c == nil {
				c = &chip{}
				chips[m[1]] = c
			}
			if m[3] == "tlv" {
				c.vers = append(c.vers, m[2])
			} else if f.Build != "" {
				c.build = f.Build
			}
		}
		if len(chips) == 0 {
			return false, nil
		}
		var prefixes []string
		for p := range chips {
			prefixes = append(prefixes, p)
		}
		sort.Strings(prefixes)
		cat, _ := catalog.Default()
		var parts []string
		for _, p := range prefixes {
			c := chips[p]
			sort.Strings(c.vers)
			name := cat.BTChipName(p)
			if name == "" {
				name = p
			}
			s := fmt.Sprintf("%s (%s)", name, strings.Join(c.vers, ", "))
			if c.build != "" {
				s = fmt.Sprintf("%s (%s; %s)", name, strings.Join(c.vers, ", "), c.build)
			}
			parts = append(parts, s)
		}
		summary := strings.Join(parts, ", ")
		if len(parts) > 1 {
			summary += " (chip is picked at runtime)"
		}
		facts.Set(b, facts.BluetoothFirmware, summary, facts.Provenance{Source: "bluetooth partition firmware", Authority: facts.Attested})
		return true, nil
	},
}
