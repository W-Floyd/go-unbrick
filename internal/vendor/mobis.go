package vendor

import (
	"github.com/W-Floyd/go-unbrick/internal/blankflash"
	"github.com/W-Floyd/go-unbrick/internal/facts"
)

// mobis: Hyundai Mobis, who builds head units for Hyundai and Kia (the hkmc
// driver reads those packages) and releases the open-source drops its products
// owe under the GPL. A vendor in its own right: its notices and source trees
// are Mobis's, whichever SoC vendor's code they modify. Only reports: there is
// no recovery path.
type mobis struct{}

func init() { Register(mobis{}) }

func (mobis) ID() string                 { return "mobis" }
func (mobis) Platform() string           { return "" }
func (mobis) OEMIDs() []string           { return nil }
func (mobis) CanIngest(path string) bool { return false }

func (mobis) IngestDonor(string) (*blankflash.Donor, error) { return nil, ErrUnsupported }
func (mobis) HarvestStock(TargetSource) (*blankflash.Target, error) {
	return nil, ErrUnsupported
}
func (mobis) Assemble(*blankflash.Donor, *blankflash.Target, AssembleOptions) (*blankflash.ForgeResult, error) {
	return nil, ErrUnsupported
}

// LearnPackage implements PackageLearner: a source release's components,
// product, dates and what its notices say Mobis changed.
func (mobis) LearnPackage(pkg PackageAccess, bag *facts.Bag) {
	learnSourceRelease(pkg, bag)
	learnUpdateVerify(pkg, bag)
}
