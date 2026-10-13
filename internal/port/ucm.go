package port

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// A draft of the board's ALSA UCM2 files from the stock audio HAL's routing.
// UCM is the distribution-neutral way a userspace (PipeWire, PulseAudio) learns
// which mixer controls bring up the speaker or the mic, so this is the
// distro-independent half of the sound port. It reproduces what the stock HAL
// does, with the stock kernel's control names: a mainline kernel's machine
// driver may name them differently, so every sequence is a starting point to
// check with alsaucm against the new kernel, not a working config.

// ucmDevices are the uses drafted, each from the HAL path that brings it up.
var ucmDevices = []struct {
	Name, Comment, Path, SndDevice string
	Playback                       bool
	Priority                       int
}{
	{"Speaker", "Speaker", "speaker", "SND_DEVICE_OUT_SPEAKER", true, 100},
	{"Earpiece", "Earpiece", "handset", "SND_DEVICE_OUT_HANDSET", true, 50},
	{"Headphones", "Headphones", "headphones", "SND_DEVICE_OUT_HEADPHONES", true, 200},
	{"Mic", "Built-in microphone", "handset-mic", "SND_DEVICE_IN_HANDSET_MIC", false, 100},
	{"HeadsetMic", "Headset microphone", "headset-mic", "SND_DEVICE_IN_HEADSET_MIC", false, 200},
}

// UCM drafts the card's UCM2 files, by bundle path. Nil when the package has no
// mixer file. notes say what was left for a person.
func UCM(p Package) (files map[string][]byte, notes []string) {
	if p.Audio == nil {
		return nil, nil
	}
	f, why := p.ChosenAudio()
	card := p.ucmCardName()
	dir := "ucm/" + card + "/"

	var b strings.Builder
	w := func(format string, a ...any) { fmt.Fprintf(&b, format+"\n", a...) }
	if why != "" {
		why = " (" + why + ")"
	}
	w("# Draft from the stock audio HAL's %s%s.", f.Name, why)
	w("# The controls are the stock kernel's. Check each with alsaucm against the new")
	w("# kernel's card: a control the machine driver names differently fails its sequence.")
	if !p.hasLiveCard() {
		w("# TODO: the card's name is the codename; set it to the new kernel's card id (/proc/asound/cards)")
	}
	w("")
	w("SectionVerb {")
	w("\tEnableSequence [")
	w("\t]")
	w("\tDisableSequence [")
	w("\t]")
	w("\tValue {")
	w("\t\tTQ \"HiFi\"")
	w("\t}")
	w("}")

	drafted, unreset := 0, 0
	for _, d := range ucmDevices {
		ctls, ok := f.Mixer.Resolve(d.Path)
		if !ok || len(ctls) == 0 {
			continue
		}
		drafted++
		enable, enableNotes := csets(ctls)
		reset, missing := resetCsets(ctls, f.Mixer.Initial)
		unreset += len(missing)

		w("")
		w("SectionDevice.\"%s\" {", d.Name)
		w("\tComment \"%s\"", d.Comment)
		w("\tEnableSequence [")
		for _, l := range enable {
			w("\t\t%s", l)
		}
		for _, n := range enableNotes {
			w("\t\t# TODO: %s", n)
		}
		w("\t]")
		w("\tDisableSequence [")
		for _, l := range reset {
			w("\t\t%s", l)
		}
		if len(missing) > 0 {
			w("\t\t# TODO: no stock initial value to restore for: %s", strings.Join(missing, ", "))
		}
		w("\t]")
		w("\tValue {")
		if d.Playback {
			w("\t\tPlaybackPriority %d", d.Priority)
			w("\t\t# TODO: PlaybackPCM \"hw:${CardId},N\": the stock DAI is %s; find its N with aplay -l on the new kernel", orDefault(f.Interfaces[d.SndDevice], "not named in the package"))
		} else {
			w("\t\tCapturePriority %d", d.Priority)
			w("\t\t# TODO: CapturePCM \"hw:${CardId},N\": the stock DAI is %s; find its N with arecord -l on the new kernel", orDefault(f.Interfaces[d.SndDevice], "not named in the package"))
		}
		w("\t}")
		w("}")
	}
	if drafted == 0 {
		return nil, nil
	}
	hifi := b.String()
	top := fmt.Sprintf("Syntax 4\n\nSectionUseCase.\"HiFi\" {\n\tFile \"HiFi.conf\"\n\tComment \"Play and record HiFi quality music\"\n}\n")
	notes = append(notes, fmt.Sprintf("ucm: drafted %d devices from %s; every PCM index is a TODO", drafted, f.Name))
	if unreset > 0 {
		notes = append(notes, fmt.Sprintf("ucm: %d controls have no stock initial value to restore on disable", unreset))
	}
	return map[string][]byte{dir + card + ".conf": []byte(top), dir + "HiFi.conf": []byte(hifi)}, notes
}

func orDefault(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

// hasLiveCard says the device named its sound card.
func (p Package) hasLiveCard() bool {
	if p.Live == nil {
		return false
	}
	for _, c := range p.Live.SoundCards {
		if c.ID != "" {
			return true
		}
	}
	return false
}

// ucmCardName is the directory and file name for the card: the live card's id,
// else the codename.
func (p Package) ucmCardName() string {
	if p.Live != nil {
		for _, c := range p.Live.SoundCards {
			if c.ID != "" {
				return c.ID
			}
		}
	}
	if _, code, _ := p.Identity(); code != "" {
		return strings.ToLower(code)
	}
	return "card"
}

// csets turns a path's controls into UCM cset lines, one per control: an array
// control set by id becomes its values in order, and anything a cset cannot say
// is a note.
func csets(ctls []MixerCtl) (lines, notes []string) {
	type entry struct {
		vals   map[int]string
		single string
		order  int
	}
	byName := map[string]*entry{}
	var names []string
	for _, c := range ctls {
		e := byName[c.Name]
		if e == nil {
			e = &entry{vals: map[int]string{}, order: len(names)}
			byName[c.Name] = e
			names = append(names, c.Name)
		}
		if c.ID == "" {
			e.single = c.Value
			continue
		}
		if i, err := strconv.Atoi(c.ID); err == nil {
			e.vals[i] = c.Value
		}
	}
	for _, n := range names {
		e := byName[n]
		v, ok := csetValue(e.single, e.vals)
		switch {
		case !ok:
			notes = append(notes, fmt.Sprintf("control %q is set by index %v: give all its values", n, sortedKeys(e.vals)))
		case strings.ContainsAny(v, " \t\"'") || strings.ContainsAny(n, "'\""):
			notes = append(notes, fmt.Sprintf("control %q = %q needs quoting for cset", n, v))
		default:
			lines = append(lines, fmt.Sprintf("cset \"name='%s' %s\"", n, v))
		}
	}
	return lines, notes
}

// csetValue is the value list for one control: its single value, or its by-id
// values when they are 0..n-1 with none missing.
func csetValue(single string, byID map[int]string) (string, bool) {
	if len(byID) == 0 {
		return single, true
	}
	vals := make([]string, len(byID))
	for i := range vals {
		v, ok := byID[i]
		if !ok {
			return "", false
		}
		vals[i] = v
	}
	return strings.Join(vals, ","), true
}

func sortedKeys(m map[int]string) []int {
	var k []int
	for i := range m {
		k = append(k, i)
	}
	sort.Ints(k)
	return k
}

// resetCsets is the disable sequence: each control the path sets, back to the
// value the HAL gives it when it opens the card. missing names the controls the
// stock file gives no initial value for.
func resetCsets(ctls []MixerCtl, initial []MixerCtl) (lines, missing []string) {
	seen := map[string]bool{}
	var want []MixerCtl
	for _, c := range ctls {
		if !seen[c.Name] {
			seen[c.Name] = true
			want = append(want, MixerCtl{Name: c.Name})
		}
	}
	// Initial values, grouped as the enable side is.
	var init []MixerCtl
	for _, w := range want {
		for _, c := range initial {
			if c.Name == w.Name {
				init = append(init, c)
			}
		}
	}
	got, _ := csets(init)
	have := map[string]bool{}
	for _, c := range init {
		have[c.Name] = true
	}
	for _, w := range want {
		if !have[w.Name] {
			missing = append(missing, w.Name)
		}
	}
	return got, missing
}
