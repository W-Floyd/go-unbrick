package port

import (
	"encoding/xml"
	"fmt"
	"io"
	"sort"
	"strings"
)

// Qualcomm's audio HAL describes routing in two files. mixer_paths*.xml names,
// per use ("speaker", "handset-mic"), the ALSA controls to set to bring that
// path up; audio_platform_info*.xml says which DAI each SND_DEVICE uses. Read
// together they are what a port's sound card and UCM files have to reproduce,
// and where the board's own codec and amplifier controls show.

// MixerPaths is a mixer file: each named path's controls, in order, and the
// paths it pulls in by name.
type MixerPaths struct {
	Paths map[string]MixerPath
}

// MixerPath is one <path>.
type MixerPath struct {
	Ctls []MixerCtl
	Uses []string // nested <path name=…/> references
}

// MixerCtl is one control setting.
type MixerCtl struct{ Name, ID, Value string }

func (c MixerCtl) String() string {
	name := c.Name
	if c.ID != "" {
		name += "[" + c.ID + "]"
	}
	return name + "=" + c.Value
}

// ParseMixerPaths reads a mixer_paths.xml. Controls outside any <path> are the
// initial settings and are not recorded.
func ParseMixerPaths(b []byte) (*MixerPaths, error) {
	d := xml.NewDecoder(strings.NewReader(string(b)))
	d.CharsetReader = func(_ string, in io.Reader) (io.Reader, error) { return in, nil } // ISO-8859-1 files are ASCII in practice
	mp := &MixerPaths{Paths: map[string]MixerPath{}}
	var stack []string // path names being read
	for {
		tok, err := d.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		switch t := tok.(type) {
		case xml.StartElement:
			switch t.Name.Local {
			case "path":
				name := attr(t, "name")
				if n := len(stack); n > 0 {
					p := mp.Paths[stack[n-1]]
					p.Uses = append(p.Uses, name)
					mp.Paths[stack[n-1]] = p
				}
				stack = append(stack, name)
			case "ctl":
				if n := len(stack); n > 0 {
					p := mp.Paths[stack[n-1]]
					p.Ctls = append(p.Ctls, MixerCtl{attr(t, "name"), attr(t, "id"), attr(t, "value")})
					mp.Paths[stack[n-1]] = p
				}
			}
		case xml.EndElement:
			if t.Name.Local == "path" && len(stack) > 0 {
				stack = stack[:len(stack)-1]
			}
		}
	}
	return mp, nil
}

func attr(t xml.StartElement, name string) string {
	for _, a := range t.Attr {
		if a.Name.Local == name {
			return a.Value
		}
	}
	return ""
}

// Resolve is a path's controls with the paths it uses expanded in place, to a
// bounded depth (references are not cyclic in practice, but the file is not
// ours).
func (m *MixerPaths) Resolve(name string) (ctls []MixerCtl, ok bool) {
	p, ok := m.Paths[name]
	if !ok {
		return nil, false
	}
	var walk func(p MixerPath, depth int)
	walk = func(p MixerPath, depth int) {
		ctls = append(ctls, p.Ctls...)
		if depth >= 4 {
			return
		}
		for _, u := range p.Uses {
			if sub, ok := m.Paths[u]; ok {
				walk(sub, depth+1)
			}
		}
	}
	walk(p, 0)
	return ctls, true
}

// PlatformInterfaces reads an audio_platform_info.xml for the DAI each
// SND_DEVICE uses: its "interface" attribute, where the file gives one.
func PlatformInterfaces(b []byte) (map[string]string, error) {
	d := xml.NewDecoder(strings.NewReader(string(b)))
	d.CharsetReader = func(_ string, in io.Reader) (io.Reader, error) { return in, nil }
	out := map[string]string{}
	for {
		tok, err := d.Token()
		if err == io.EOF {
			return out, nil
		}
		if err != nil {
			return out, err
		}
		if t, ok := tok.(xml.StartElement); ok && t.Name.Local == "device" {
			if name, itf := attr(t, "name"), attr(t, "interface"); name != "" && itf != "" {
				if _, dup := out[name]; !dup {
					out[name] = itf
				}
			}
		}
	}
}

// AudioFile is one mixer file with the platform file that pairs with it.
type AudioFile struct {
	Name       string // "etc/mixer_paths_qrd.xml"
	Mixer      *MixerPaths
	Interfaces map[string]string // from the same-suffix audio_platform_info
}

// Audio is every mixer file the vendor partition carries. A package ships
// several (the SoC reference and per-board variants) and does not say which
// sound card picks which; the running device's card name does.
type Audio struct{ Files []AudioFile }

// audioDevices are the uses a port needs first, each with the HAL path that
// brings it up and the platform device that names its interface.
var audioDevices = []struct{ Use, Path, SndDevice string }{
	{"speaker", "speaker", "SND_DEVICE_OUT_SPEAKER"},
	{"handset (earpiece)", "handset", "SND_DEVICE_OUT_HANDSET"},
	{"headphones", "headphones", "SND_DEVICE_OUT_HEADPHONES"},
	{"built-in mic", "handset-mic", "SND_DEVICE_IN_HANDSET_MIC"},
	{"speaker mic", "speaker-mic", "SND_DEVICE_IN_SPEAKER_MIC"},
	{"headset mic", "headset-mic", "SND_DEVICE_IN_HEADSET_MIC"},
}

// ReadAudio builds Audio from the vendor partition's files, read by name
// through read. nil when no mixer file is present.
func ReadAudio(files []string, read func(name string) ([]byte, error)) *Audio {
	var a Audio
	sort.Strings(files)
	for _, f := range files {
		base := f[strings.LastIndex(f, "/")+1:]
		if !strings.HasPrefix(f, "etc/mixer_paths") || !strings.HasSuffix(base, ".xml") {
			continue
		}
		b, err := read(f)
		if err != nil {
			continue
		}
		mp, err := ParseMixerPaths(b)
		if err != nil || len(mp.Paths) == 0 {
			continue
		}
		af := AudioFile{Name: f, Mixer: mp, Interfaces: map[string]string{}}
		suffix := strings.TrimSuffix(strings.TrimPrefix(base, "mixer_paths"), ".xml")
		pb, err := read("etc/audio_platform_info" + suffix + ".xml")
		if err != nil {
			pb, err = read("etc/audio_platform_info.xml") // no file for this variant: the shared one
		}
		if err == nil {
			af.Interfaces, _ = PlatformInterfaces(pb)
		}
		a.Files = append(a.Files, af)
	}
	if len(a.Files) == 0 {
		return nil
	}
	return &a
}

// ChosenAudio is the mixer file this board uses, and what says so: of the
// package's files, those installed on the live device, then the one whose name
// shares the most words with the sound card's id (a card "bengal-scubaidp-snd-
// card" takes mixer_paths_scubaidp.xml). With no live device, or no evidence,
// it is the shared mixer_paths.xml, or the first file, and why is empty.
func (p Package) ChosenAudio() (f AudioFile, why string) {
	a := p.Audio
	cands := a.Files
	if p.Live != nil && len(p.Live.MixerFiles) > 0 {
		var installed []AudioFile
		for _, af := range cands {
			for _, name := range p.Live.MixerFiles {
				if strings.HasSuffix(af.Name, "/"+name) {
					installed = append(installed, af)
				}
			}
		}
		switch len(installed) {
		case 0:
		case 1:
			return installed[0], "the only mixer file installed on the device"
		default:
			cands = installed
		}
	}
	if p.Live != nil {
		for _, c := range p.Live.SoundCards {
			if best, ok := bestByWords(cands, c.ID); ok && c.ID != "" {
				return best, fmt.Sprintf("its name matches the device's sound card %q", c.ID)
			}
		}
	}
	for _, af := range cands {
		if af.Name == "etc/mixer_paths.xml" {
			return af, ""
		}
	}
	return cands[0], ""
}

// bestByWords is the file whose name shares the most words with id, if one
// does uniquely.
func bestByWords(files []AudioFile, id string) (AudioFile, bool) {
	words := func(s string) map[string]bool {
		m := map[string]bool{}
		for _, w := range strings.FieldsFunc(strings.ToLower(s), func(r rune) bool { return r == '-' || r == '_' || r == '.' || r == '/' }) {
			if w != "snd" && w != "card" && w != "mixer" && w != "paths" && w != "xml" && w != "etc" {
				m[w] = true
			}
		}
		return m
	}
	have := words(id)
	var best AudioFile
	bestN, tie := 0, false
	for _, f := range files {
		n := 0
		for w := range words(f.Name) {
			if have[w] {
				n++
			}
		}
		switch {
		case n > bestN:
			best, bestN, tie = f, n, false
		case n == bestN && n > 0:
			tie = true
		}
	}
	return best, bestN > 0 && !tie
}

// AudioSection is the report's account of the audio routing.
func AudioSection(p Package) string {
	a := p.Audio
	if a == nil {
		return ""
	}
	var b strings.Builder
	w := func(f string, a ...any) { fmt.Fprintf(&b, f+"\n", a...) }
	w("\n## Audio routing\n")
	w("What the stock audio HAL does to bring up each use: the DAI from `audio_platform_info`, and the controls its `mixer_paths` path sets. The package carries %d mixer file(s); which one a unit uses follows its sound card's name, which only a running device reports (`--live`).\n", len(a.Files))
	first, why := p.ChosenAudio()
	if why != "" {
		w("From `%s` (%s):\n", first.Name, why)
	} else {
		w("From `%s`:\n", first.Name)
	}
	w("| use | DAI | controls |")
	w("|---|---|---|")
	for _, d := range audioDevices {
		ctls, ok := first.Mixer.Resolve(d.Path)
		if !ok {
			continue
		}
		itf := first.Interfaces[d.SndDevice]
		if itf == "" {
			itf = "—"
		}
		w("| %s | %s | %s |", d.Use, itf, ctlSummary(ctls, 8))
	}
	// Where variants disagree on a core path, that is board-specific.
	var diff []string
	for _, f := range a.Files {
		if f.Name == first.Name {
			continue
		}
		for _, d := range audioDevices {
			x, _ := first.Mixer.Resolve(d.Path)
			y, ok := f.Mixer.Resolve(d.Path)
			if ok && ctlSummary(x, 1<<30) != ctlSummary(y, 1<<30) {
				diff = append(diff, fmt.Sprintf("`%s` in `%s`", d.Path, f.Name))
			}
		}
	}
	if len(diff) > 0 {
		w("\nDiffers from `%s`: %s.", first.Name, strings.Join(diff, "; "))
	}
	return b.String()
}

func ctlSummary(ctls []MixerCtl, max int) string {
	var parts []string
	for i, c := range ctls {
		if i == max {
			parts = append(parts, fmt.Sprintf("(+%d)", len(ctls)-max))
			break
		}
		parts = append(parts, "`"+c.String()+"`")
	}
	if len(parts) == 0 {
		return "none"
	}
	return strings.Join(parts, ", ")
}
