package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/W-Floyd/go-unbrick/internal/carve"
	"github.com/W-Floyd/go-unbrick/internal/filetype"
	"github.com/W-Floyd/go-unbrick/internal/srcfile"
)

// maxNestedZip caps the zip copied to disk to read inside it.
const maxNestedZip = 8 << 30

// nestedZipDepth is how many zips deep printNestedZip has gone, against reconDepth.
var nestedZipDepth int

// printNestedZip describes a zip member too big to buffer by walking it through
// carve, which reads encrypted members with the vendor's password and needs no
// copy to do it. A zip inside is the one thing recon can only read from a file, so
// it is copied to a temp file (already decrypted) and reported on in full. false
// when m cannot be walked; nothing is printed then.
func printNestedZip(path string, m srcfile.Member, indent string) bool {
	if nestedZipDepth >= reconDepth-1 {
		return false
	}
	n, err := carvePath(path, m.Name)
	if err != nil || !n.RandomAccess() {
		return false
	}
	_, kids, err := n.Children()
	if err != nil || len(kids) == 0 {
		return false
	}
	nestedZipDepth++
	defer func() { nestedZipDepth-- }()
	fmt.Printf("%s%-26s [zip]  %s, %d member(s)\n", indent, filepath.Base(m.Name), humanBytes(int64(m.Size)), len(kids))
	for _, k := range kids {
		base := filepath.Base(k.Name)
		head := k.Head()
		if filetype.Detect(head) == filetype.Zip && k.Size <= maxNestedZip && reconZipMember(k, indent+"  ") {
			continue
		}
		fmt.Printf("%s  %-24s [%s]  %s\n", indent, base, typeLabel(base, head), humanBytes(k.Size))
	}
	return true
}

// reconZipMember reports on a zip node as recon would on a file of its own, under
// indent. false if it could not be read, with nothing printed.
func reconZipMember(k *carve.Node, indent string) bool {
	ra, err := k.ReaderAt()
	if err != nil {
		return false
	}
	dir, err := os.MkdirTemp("", "unbrick-nested-")
	if err != nil {
		return false
	}
	defer os.RemoveAll(dir)
	tmp := filepath.Join(dir, filepath.Base(k.Name))
	f, err := os.Create(tmp)
	if err != nil {
		return false
	}
	_, err = io.Copy(f, io.NewSectionReader(ra, 0, k.Size))
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil || !srcfile.IsArchive(tmp) {
		return false
	}
	bag, _, _, err := reconIngest(tmp, "", true)
	if err != nil {
		return false
	}
	fmt.Printf("%s%s\n", indent, filepath.Base(k.Name))
	fmt.Printf("%s  Size:  %s\n", indent, humanBytes(k.Size))
	withIndent(indent, func() { reconArchive(tmp, bag) })
	return true
}

// withIndent runs f with what it prints to stdout prefixed by indent.
func withIndent(indent string, f func()) {
	r, w, err := os.Pipe()
	if err != nil {
		f()
		return
	}
	out := os.Stdout
	os.Stdout = w
	done := make(chan struct{})
	go func() {
		defer close(done)
		s := bufio.NewScanner(r)
		s.Buffer(make([]byte, 1<<20), 1<<24)
		for s.Scan() {
			if line := s.Text(); strings.TrimSpace(line) == "" {
				fmt.Fprintln(out)
			} else {
				fmt.Fprintln(out, indent+line)
			}
		}
	}()
	defer func() {
		w.Close()
		<-done
		r.Close()
		os.Stdout = out
	}()
	f()
}
