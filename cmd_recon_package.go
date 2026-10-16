package main

import (
	"github.com/W-Floyd/go-unbrick/internal/facts"
	"github.com/W-Floyd/go-unbrick/internal/srcfile"
	"github.com/W-Floyd/go-unbrick/internal/vendor"
)

// learnPackageFacts lets each vendor read its own package members into the bag.
func learnPackageFacts(path string, bag *facts.Bag) {
	members, err := srcfile.Members(path, 0)
	if err != nil {
		return
	}
	names := map[string]bool{}
	for _, m := range members {
		names[m.Name] = true
	}
	vendor.LearnPackage(vendor.PackageAccess{
		Names: names,
		Read: func(name string) []byte {
			n, err := carvePath(path, name)
			if err != nil {
				return nil
			}
			b, _ := n.Bytes()
			return b
		},
		Decrypts: func() bool { return len(reconSecrets) > 0 },
	}, bag)
}
