package provision

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// apkBytes stands in for a release asset; its digest is what a recipe would pin.
var apkBytes = []byte("PK\x03\x04 not really an apk, but it has bytes")

func apkDigest() string {
	sum := sha256.Sum256(apkBytes)
	return hex.EncodeToString(sum[:])
}

// ghServer serves a GitHub-shaped release plus the asset itself, so the fetch
// path is exercised without reaching the network.
func ghServer(t *testing.T, assets ...string) *httptest.Server {
	t.Helper()
	var srv *httptest.Server
	mux := http.NewServeMux()
	mux.HandleFunc("/repos/owner/repo/releases/latest", func(w http.ResponseWriter, r *http.Request) {
		var items []string
		for _, name := range assets {
			items = append(items, fmt.Sprintf(`{"name":%q,"browser_download_url":%q,"size":%d}`,
				name, srv.URL+"/download/"+name, len(apkBytes)))
		}
		fmt.Fprintf(w, `{"tag_name":"v1.2.3","assets":[%s]}`, strings.Join(items, ","))
	})
	mux.HandleFunc("/repos/owner/repo/releases/tags/v0.9", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `{"tag_name":"v0.9","assets":[{"name":"old.apk","browser_download_url":%q,"size":%d}]}`,
			srv.URL+"/download/old.apk", len(apkBytes))
	})
	mux.HandleFunc("/download/", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(apkBytes)
	})
	srv = httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func fetcher(t *testing.T, srv *httptest.Server) *Fetcher {
	t.Helper()
	return &Fetcher{
		CacheDir: t.TempDir(),
		APIBase:  srv.URL,
		GH:       "none", // the real gh would talk to the real GitHub
	}
}

func oneInstall(spec APKSpec) (*Profile, []Action) {
	p := &Profile{ID: "x", APK: spec, Steps: []Step{{Install: &InstallStep{Reinstall: true}}}}
	actions, _ := p.Render(nil)
	return p, actions
}

func TestResolveAndFetch(t *testing.T) {
	srv := ghServer(t, "app-full-release.apk", "app-minimal-release.apk")
	f := fetcher(t, srv)
	p, actions := oneInstall(APKSpec{Source: "github:owner/repo", Asset: "app-full-release.apk"})

	sources, err := f.Resolve(p, actions, nil)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if len(sources) != 1 {
		t.Fatalf("resolved %d sources", len(sources))
	}
	s := sources[0]
	if s.Name != "app-full-release.apk" || s.Tag != "v1.2.3" {
		t.Errorf("resolved %+v", s)
	}
	if s.Have {
		t.Error("an empty cache reported a hit")
	}
	// Resolve must not download: the plan is printed before anything is fetched.
	if _, err := os.Stat(s.Cached); err == nil {
		t.Error("Resolve wrote the file")
	}

	path, digest, err := f.Get(s)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if digest != apkDigest() {
		t.Errorf("digest = %s, want %s", digest, apkDigest())
	}
	got, _ := os.ReadFile(path)
	if string(got) != string(apkBytes) {
		t.Error("the downloaded file is not what the server sent")
	}

	// Second time it comes from the cache, keyed by tag and asset.
	again, err := f.Resolve(p, actions, nil)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if !again[0].Have {
		t.Error("the cached file was not seen on a second resolve")
	}
	if !strings.Contains(again[0].Cached, "v1.2.3") {
		t.Errorf("cache path does not key by tag: %s", again[0].Cached)
	}
}

// A pin is the difference between "some build of this app" and "this build".
func TestPinIsEnforced(t *testing.T) {
	srv := ghServer(t, "app.apk")
	f := fetcher(t, srv)

	good, actions := oneInstall(APKSpec{Source: "github:owner/repo", SHA256: apkDigest()})
	sources, err := f.Resolve(good, actions, nil)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if _, _, err := f.Get(sources[0]); err != nil {
		t.Errorf("a matching pin was rejected: %v", err)
	}

	bad, actions2 := oneInstall(APKSpec{Source: "github:owner/repo", SHA256: strings.Repeat("ab", 32)})
	f2 := fetcher(t, srv)
	sources2, err := f2.Resolve(bad, actions2, nil)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	_, _, err = f2.Get(sources2[0])
	if err == nil {
		t.Fatal("a mismatched pin was accepted")
	}
	if !strings.Contains(err.Error(), "does not match the recipe's pin") {
		t.Errorf("error = %v", err)
	}
	// The downloaded file is kept for inspection rather than deleted, but it
	// must not be handed to the installer — Get returned no path.
}

// A cached file that stops matching the pin is not silently replaced: someone
// changed the pin or the cache, and both are worth hearing about.
func TestCachedFileAgainstAChangedPin(t *testing.T) {
	srv := ghServer(t, "app.apk")
	f := fetcher(t, srv)
	p, actions := oneInstall(APKSpec{Source: "github:owner/repo"})
	sources, _ := f.Resolve(p, actions, nil)
	if _, _, err := f.Get(sources[0]); err != nil {
		t.Fatalf("Get: %v", err)
	}

	// Same cache, now with a pin that does not match what is in it.
	pinned, actions2 := oneInstall(APKSpec{Source: "github:owner/repo", SHA256: strings.Repeat("cd", 32)})
	sources2, _ := f.Resolve(pinned, actions2, nil)
	if !sources2[0].Have {
		t.Fatal("the cached file was not found")
	}
	_, _, err := f.Get(sources2[0])
	if err == nil || !strings.Contains(err.Error(), "cached") {
		t.Errorf("error = %v, want one naming the cached file", err)
	}
}

func TestAssetSelection(t *testing.T) {
	assets := []ghAsset{
		{Name: "app-full-release.apk"},
		{Name: "app-minimal-release.apk"},
		{Name: "locales_config.xml"},
	}
	// A pattern picks one…
	if a, err := pickAsset(assets, "app-full-release.apk"); err != nil || a.Name != "app-full-release.apk" {
		t.Errorf("pickAsset = %+v, %v", a, err)
	}
	if a, err := pickAsset(assets, "*minimal*"); err != nil || a.Name != "app-minimal-release.apk" {
		t.Errorf("glob pickAsset = %+v, %v", a, err)
	}
	// …and with several APKs and no pattern, choosing silently would be the
	// wrong kind of helpful: full and minimal install different packages.
	_, err := pickAsset(assets, "")
	if err == nil {
		t.Fatal("two APKs and no pattern was resolved anyway")
	}
	if !strings.Contains(err.Error(), "app-full-release.apk") {
		t.Errorf("the error does not list the choices: %v", err)
	}
	// One APK needs no pattern.
	if a, err := pickAsset([]ghAsset{{Name: "only.apk"}, {Name: "notes.txt"}}, ""); err != nil || a.Name != "only.apk" {
		t.Errorf("single-APK release: %+v, %v", a, err)
	}
	// An ambiguous pattern is an error, not a coin toss.
	if _, err := pickAsset(assets, "app-*.apk"); err == nil {
		t.Error("an ambiguous pattern resolved")
	}
	if _, err := pickAsset(assets, "nothing-like-this"); err == nil {
		t.Error("a pattern matching nothing resolved")
	}
	if _, err := pickAsset([]ghAsset{{Name: "notes.txt"}}, ""); err == nil {
		t.Error("a release with no APK resolved")
	}
}

func TestTagOverride(t *testing.T) {
	srv := ghServer(t, "app.apk")
	f := fetcher(t, srv)
	f.TagOverride = map[string]string{"": "v0.9"}
	p, actions := oneInstall(APKSpec{Source: "github:owner/repo"})

	sources, err := f.Resolve(p, actions, nil)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if sources[0].Tag != "v0.9" || sources[0].Name != "old.apk" {
		t.Errorf("resolved %+v, want the overridden tag", sources[0])
	}
}

func TestAssetOverride(t *testing.T) {
	srv := ghServer(t, "app-full-release.apk", "app-minimal-release.apk")
	f := fetcher(t, srv)
	f.AssetOverride = map[string]string{"": "app-minimal-release.apk"}
	p, actions := oneInstall(APKSpec{Source: "github:owner/repo", Asset: "app-full-release.apk"})

	sources, err := f.Resolve(p, actions, nil)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if sources[0].Name != "app-minimal-release.apk" {
		t.Errorf("resolved %q, want the override", sources[0].Name)
	}
}

// --apk wins: a file the operator points at is never second-guessed by a fetch.
func TestLocalFileSkipsFetching(t *testing.T) {
	f := &Fetcher{CacheDir: t.TempDir(), APIBase: "http://127.0.0.1:0", GH: "none"}
	p, actions := oneInstall(APKSpec{Source: "github:owner/repo"})
	sources, err := f.Resolve(p, actions, map[string]string{"": "/tmp/mine.apk"})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if len(sources) != 0 {
		t.Errorf("resolved %d sources though the file was given", len(sources))
	}
}

// Offline must not reach the network, and must say what to do instead.
func TestOfflineRefusesToFetch(t *testing.T) {
	srv := ghServer(t, "app.apk")
	f := fetcher(t, srv)
	p, actions := oneInstall(APKSpec{Source: "github:owner/repo"})
	sources, _ := f.Resolve(p, actions, nil)

	f.Offline = true
	_, _, err := f.Get(sources[0])
	if err == nil {
		t.Fatal("an offline fetcher downloaded")
	}
	if !strings.Contains(err.Error(), "--apk") {
		t.Errorf("the error does not say what to do instead: %v", err)
	}
	// Resolving a GitHub source offline is refused too, since it is a request.
	f2 := fetcher(t, srv)
	f2.Offline = true
	if _, err := f2.Resolve(p, actions, nil); err == nil {
		t.Error("an offline fetcher asked GitHub for release metadata")
	}
}

func TestGitHubSourceForms(t *testing.T) {
	for _, in := range []string{
		"github:owner/repo",
		"https://github.com/owner/repo",
		"https://github.com/owner/repo/releases",
	} {
		owner, repo, ok := gitHubRepo(in)
		if !ok || owner != "owner" || repo != "repo" {
			t.Errorf("gitHubRepo(%q) = %q/%q/%v", in, owner, repo, ok)
		}
	}
	for _, in := range []string{"https://example.invalid/app.apk", "github:owner", ""} {
		if _, _, ok := gitHubRepo(in); ok {
			t.Errorf("gitHubRepo(%q) claimed to be a repo", in)
		}
	}
}

// A direct URL is allowed, and must be an APK — a recipe pointing at a release
// *page* would otherwise download HTML and install it.
func TestDirectURL(t *testing.T) {
	srv := ghServer(t, "app.apk")
	f := fetcher(t, srv)
	p, actions := oneInstall(APKSpec{Source: srv.URL + "/download/app.apk"})
	sources, err := f.Resolve(p, actions, nil)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if sources[0].Name != "app.apk" {
		t.Errorf("resolved %+v", sources[0])
	}
	if _, digest, err := f.Get(sources[0]); err != nil || digest != apkDigest() {
		t.Errorf("Get = %q, %v", digest, err)
	}

	bad, actions2 := oneInstall(APKSpec{Source: "https://example.invalid/releases"})
	if _, err := f.Resolve(bad, actions2, nil); err == nil {
		t.Error("a non-APK URL was accepted")
	}
}

// A cache path must not be escapable by a tag or asset name, both of which come
// off the network. The test is containment, not the absence of dots: a name
// sanitised to "_.._etc" is one harmless path element that happens to contain
// two of them.
func TestCachePathIsContained(t *testing.T) {
	f := &Fetcher{CacheDir: "/tmp/cache"}
	got := filepath.Clean(f.cachePath("ha", "../../etc", "../../../passwd"))

	if !strings.HasPrefix(got, "/tmp/cache"+string(filepath.Separator)) {
		t.Errorf("cachePath left the cache dir: %s", got)
	}
	for _, part := range strings.Split(got, string(filepath.Separator)) {
		if part == ".." {
			t.Errorf("cachePath has a traversing element: %s", got)
		}
	}
	// A name that sanitises to nothing still yields a usable file.
	if base := filepath.Base(f.cachePath("", "", "...")); base == "" || base == "." {
		t.Errorf("cachePath of an empty name = %q", base)
	}
}
