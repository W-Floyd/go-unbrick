package analysis

import (
	"net/url"
	"strings"
)

// Location is a place in a comparison: a level (the entry names gone through from
// the top), the entry selected in it, and how it is being looked at. It has a
// text form, so a front end can keep it in a URL and an embedding tool can build
// a link to it:
//
//	p=sub%2F&p=pkg.tar%2F&sel=enc_boot.img&view=hex&words=0
//
// The web page keeps exactly this in its URL fragment.
type Location struct {
	Path    []string // entry names from the top, as Entry.Name: "sub/", "pkg.tar/"
	Entry   string   // the entry selected in that level; "" for none
	View    View     // "" is ViewAuto
	NoWords bool     // words within changed lines are not marked
}

// Fragment is the location as a query string (no leading "#" or "?").
func (l Location) Fragment() string {
	v := url.Values{}
	for _, p := range l.Path {
		v.Add("p", p)
	}
	if l.Entry != "" {
		v.Set("sel", l.Entry)
	}
	if l.View != "" && l.View != ViewAuto {
		v.Set("view", string(l.View))
	}
	if l.NoWords {
		v.Set("words", "0")
	}
	// url.Values.Encode sorts by key, which would put sel before p: build in order.
	var parts []string
	for _, p := range l.Path {
		parts = append(parts, "p="+url.QueryEscape(p))
	}
	for _, k := range []string{"sel", "view", "words"} {
		if x := v.Get(k); x != "" {
			parts = append(parts, k+"="+url.QueryEscape(x))
		}
	}
	return strings.Join(parts, "&")
}

// ParseLocation reads a location back; a leading "#" or "?" is allowed, and what
// it does not understand is ignored.
func ParseLocation(s string) Location {
	s = strings.TrimLeft(s, "#?")
	v, _ := url.ParseQuery(s)
	l := Location{Path: v["p"], Entry: v.Get("sel"), NoWords: v.Get("words") == "0"}
	switch View(v.Get("view")) {
	case ViewStrings:
		l.View = ViewStrings
	case ViewOverlap:
		l.View = ViewOverlap
	case ViewHex:
		l.View = ViewHex
	}
	return l
}

// LevelAt is the level at a path of entry names from the top, opened on first use
// and kept (a container's members level is a comparison of its own). It fails
// with ErrNoSuchEntry for a name the level does not have (yet: while the
// comparison runs it may be found later) and with Open's error for one with
// nowhere to go.
func (r *Run) LevelAt(path []string) (*Level, error) {
	return r.lc.at(r.Root(), path, func(cur *Level, name string) (*Level, error) {
		e, ok := findEntry(r.Entries(cur, false), name)
		if !ok {
			return nil, ErrNoSuchEntry
		}
		return r.Open(cur, e)
	})
}

// Locate is the level and, if loc names one, the entry in it.
func (r *Run) Locate(loc Location) (*Level, Entry, error) {
	l, err := r.LevelAt(loc.Path)
	if err != nil || loc.Entry == "" {
		return l, Entry{}, err
	}
	e, ok := findEntry(r.Entries(l, false), loc.Entry)
	if !ok {
		return l, Entry{}, ErrNoSuchEntry
	}
	return l, e, nil
}

// FindEntry is the entry called name in a list of entries.
func FindEntry(es []Entry, name string) (Entry, bool) { return findEntry(es, name) }

func findEntry(es []Entry, name string) (Entry, bool) {
	for _, e := range es {
		if e.Name == name {
			return e, true
		}
	}
	return Entry{}, false
}
