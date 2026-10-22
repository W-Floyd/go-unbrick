package web

import (
	"regexp"
	"strings"
	"testing"
)

// The pages follow the system's light or dark setting natively: they say so, so form controls,
// scrollbars and the like are drawn to match and there is no white flash while they load; they have a
// dark palette; and every colour outside the palette definitions is one of its variables.
func TestPagesFollowTheSystemColourScheme(t *testing.T) {
	for _, name := range []string{"static/index.html", "static/browse.html"} {
		b, err := assets.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		for _, want := range []string{`<meta name="color-scheme" content="light dark">`, `media="(prefers-color-scheme: dark)"`} {
			if !strings.Contains(string(b), want) {
				t.Errorf("%s lacks %q", name, want)
			}
		}
	}
	b, err := assets.ReadFile("static/style.css")
	if err != nil {
		t.Fatal(err)
	}
	css := string(b)
	for _, want := range []string{"color-scheme: light dark", "@media (prefers-color-scheme: dark)"} {
		if !strings.Contains(css, want) {
			t.Errorf("style.css lacks %q", want)
		}
	}
	rest := regexp.MustCompile(`(?s)(@media \(prefers-color-scheme: dark\) \{\s*)?:root\s*\{.*?\}(\s*\})?`).ReplaceAllString(css, "")
	for _, m := range regexp.MustCompile(`#[0-9a-fA-F]{3,8}\b`).FindAllString(rest, -1) {
		t.Errorf("style.css has a fixed colour %s outside the palette: dark mode would not reach it", m)
	}
}
