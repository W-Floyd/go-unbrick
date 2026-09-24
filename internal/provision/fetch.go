package provision

// Getting the APKs a recipe installs.
//
// This tool now fetches them, which deserves saying out loud: downloading a
// binary and installing it on someone's phone is the most consequential thing
// here, so it comes with the things that make it checkable rather than merely
// convenient.
//
//   - The plan names the exact asset, release tag and URL *before* anything is
//     fetched, and the fetch itself only happens under --apply.
//   - A recipe may pin `sha256`, which is verified before install and refuses
//     on a mismatch. Where it does not, the digest of what was downloaded is
//     printed and written into the record, so the next run can pin it.
//   - Downloads are cached by release tag and asset name, so a second run
//     installs the same bytes rather than whatever upstream published since.
//   - `gh` is used when the source is GitHub and the CLI is present: it brings
//     the operator's own auth and rate limit. Plain HTTPS is the fallback.
//   - `--apk name=<file>` still wins, and `--no-download` refuses the network
//     outright.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strings"
	"time"
)

// Source is a resolved download: what will be fetched, from where.
type Source struct {
	APK  string // the recipe's APK name ("" for a single unnamed one)
	URL  string
	Name string // asset filename
	Tag  string // release tag it came from
	Size int64
	// SHA256 is the recipe's pin, empty when it pins nothing.
	SHA256 string
	// Cached is where it lands, and whether it is already there.
	Cached string
	Have   bool
}

// Describe is the one-line form a plan prints.
func (s Source) Describe() string {
	where := s.URL
	if s.Tag != "" {
		where = fmt.Sprintf("%s (%s)", s.URL, s.Tag)
	}
	switch {
	case s.Have && s.SHA256 != "":
		return fmt.Sprintf("%s — cached, digest pinned by the recipe", s.Name)
	case s.Have:
		return fmt.Sprintf("%s — already cached at %s", s.Name, s.Cached)
	case s.SHA256 != "":
		return fmt.Sprintf("%s from %s, digest pinned by the recipe", s.Name, where)
	}
	return fmt.Sprintf("%s from %s", s.Name, where)
}

// Fetcher resolves and downloads a recipe's APKs into a cache directory.
type Fetcher struct {
	// CacheDir is where downloads are kept, keyed by tag and asset name.
	CacheDir string
	// Offline refuses any network access, for a run that must only use what is
	// already cached or passed with --apk.
	Offline bool
	// Client is the HTTP client for a non-GitHub source or when gh is absent.
	Client *http.Client
	// GH is the gh binary; empty resolves it from PATH, "none" disables it.
	GH string
	// APIBase is the GitHub API root, for tests. Empty means the real one.
	APIBase string
	// AssetOverride and TagOverride are the operator's per-APK overrides.
	AssetOverride map[string]string
	TagOverride   map[string]string
}

// httpClient is the client to use, with a timeout that suits a ~50 MB APK on a
// domestic connection rather than the zero value's "forever".
func (f *Fetcher) httpClient() *http.Client {
	if f.Client != nil {
		return f.Client
	}
	return &http.Client{Timeout: 10 * time.Minute}
}

// Resolve works out what would be fetched for each install step, without
// downloading anything. It is what the plan prints.
func (f *Fetcher) Resolve(p *Profile, actions []Action, have map[string]string) ([]Source, error) {
	var out []Source
	for _, a := range actions {
		if !a.Install {
			continue
		}
		if have[a.APKName] != "" {
			continue // the operator passed a file; nothing to fetch
		}
		spec, ok := p.APKFor(a.APKName)
		if !ok || spec.Source == "" {
			return nil, fmt.Errorf("%s installs %s but the recipe says where to get it: pass it with --apk %s=<file>",
				p.ID, orThisApp(a.APKName), orThisApp(a.APKName))
		}
		src, err := f.resolveOne(a.APKName, spec)
		if err != nil {
			return nil, err
		}
		out = append(out, src)
	}
	return out, nil
}

func (f *Fetcher) resolveOne(name string, spec APKSpec) (Source, error) {
	src := Source{APK: name, SHA256: spec.SHA256}
	asset := spec.Asset
	if o := f.AssetOverride[name]; o != "" {
		asset = o
	}
	tag := spec.Tag
	if o := f.TagOverride[name]; o != "" {
		tag = o
	}

	owner, repo, isGitHub := gitHubRepo(spec.Source)
	switch {
	case isGitHub:
		rel, err := f.release(owner, repo, tag)
		if err != nil {
			return src, err
		}
		a, err := pickAsset(rel.Assets, asset)
		if err != nil {
			return src, fmt.Errorf("%s/%s %s: %w", owner, repo, rel.TagName, err)
		}
		src.URL, src.Name, src.Size, src.Tag = a.URL, a.Name, a.Size, rel.TagName
	default:
		// A direct URL: the asset name is its last path element.
		src.URL = spec.Source
		src.Name = path.Base(spec.Source)
		if !strings.HasSuffix(strings.ToLower(src.Name), ".apk") {
			return src, fmt.Errorf("%s does not look like an APK URL — give the recipe a github: source and an asset, or pass --apk %s=<file>",
				spec.Source, orThisApp(name))
		}
	}

	src.Cached = f.cachePath(name, src.Tag, src.Name)
	if st, err := os.Stat(src.Cached); err == nil && st.Size() > 0 {
		src.Have = true
	}
	return src, nil
}

// cachePath keys a download by APK name, release tag and asset name, so two
// tags of one app coexist and a re-run installs the same bytes it did before.
func (f *Fetcher) cachePath(name, tag, asset string) string {
	dir := f.CacheDir
	if dir == "" {
		dir = filepath.Join(os.TempDir(), "unbrick-apks")
	}
	parts := []string{dir}
	if name != "" {
		parts = append(parts, sanitizePathPart(name))
	}
	if tag != "" {
		parts = append(parts, sanitizePathPart(tag))
	}
	return filepath.Join(append(parts, sanitizePathPart(asset))...)
}

// Get returns a local file for a source, downloading it if the cache has no
// copy. It returns the file's digest either way, which is what a run prints and
// records: a recipe that pins nothing should still tell the operator what it
// just installed.
func (f *Fetcher) Get(src Source) (path, digest string, err error) {
	if src.Have {
		d, derr := fileDigest(src.Cached)
		if derr != nil {
			return "", "", derr
		}
		if src.SHA256 != "" && !strings.EqualFold(d, src.SHA256) {
			// A cached file that no longer matches the pin is not the file the
			// recipe means. Refuse rather than silently re-download: someone
			// changed either the pin or the cache, and both are worth knowing.
			return "", "", fmt.Errorf("the cached %s does not match the recipe's pin (have %s, want %s) — delete %s to fetch it again",
				src.Name, d, src.SHA256, src.Cached)
		}
		return src.Cached, d, nil
	}
	if f.Offline {
		return "", "", fmt.Errorf("%s is not cached and --no-download was given: pass it with --apk %s=<file>",
			src.Name, orThisApp(src.APK))
	}
	if err := f.download(src); err != nil {
		return "", "", err
	}
	d, derr := fileDigest(src.Cached)
	if derr != nil {
		return "", "", derr
	}
	if src.SHA256 != "" && !strings.EqualFold(d, src.SHA256) {
		// Keep the file for inspection but do not hand it to the installer.
		return "", "", fmt.Errorf("%s does not match the recipe's pin: downloaded %s, recipe pins %s (kept at %s)",
			src.Name, d, src.SHA256, src.Cached)
	}
	return src.Cached, d, nil
}

// download writes the asset to its cache path, via a temporary file so an
// interrupted transfer never looks like a complete one.
func (f *Fetcher) download(src Source) error {
	if err := os.MkdirAll(filepath.Dir(src.Cached), 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(src.Cached), ".partial-*")
	if err != nil {
		return err
	}
	defer func() {
		tmp.Close()
		os.Remove(tmp.Name())
	}()

	resp, err := f.httpClient().Get(src.URL)
	if err != nil {
		return fmt.Errorf("downloading %s: %w", src.Name, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("downloading %s: %s", src.Name, resp.Status)
	}
	n, err := io.Copy(tmp, resp.Body)
	if err != nil {
		return fmt.Errorf("downloading %s: %w", src.Name, err)
	}
	if n == 0 {
		return fmt.Errorf("downloading %s: the server sent nothing", src.Name)
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), src.Cached)
}

// release fetches release metadata, preferring the gh CLI when the operator has
// it: gh carries their credentials and rate limit, which matters because the
// anonymous GitHub API allows 60 requests an hour and a private repo none.
func (f *Fetcher) release(owner, repo, tag string) (ghRelease, error) {
	if f.Offline {
		return ghRelease{}, fmt.Errorf("resolving %s/%s needs the network and --no-download was given", owner, repo)
	}
	endpoint := fmt.Sprintf("repos/%s/%s/releases/latest", owner, repo)
	if tag != "" && tag != "latest" {
		endpoint = fmt.Sprintf("repos/%s/%s/releases/tags/%s", owner, repo, tag)
	}

	if bin := f.ghBinary(); bin != "" {
		out, err := exec.Command(bin, "api", endpoint).Output()
		if err == nil {
			var rel ghRelease
			if jerr := json.Unmarshal(out, &rel); jerr == nil && len(rel.Assets) > 0 {
				return rel, nil
			}
		}
		// gh failed (not logged in, no network, an API change): fall through to
		// plain HTTPS rather than giving up, and let that error speak.
	}

	base := f.APIBase
	if base == "" {
		base = "https://api.github.com/"
	}
	req, err := http.NewRequest(http.MethodGet, strings.TrimSuffix(base, "/")+"/"+endpoint, nil)
	if err != nil {
		return ghRelease{}, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := f.httpClient().Do(req)
	if err != nil {
		return ghRelease{}, fmt.Errorf("asking GitHub about %s/%s: %w", owner, repo, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		hint := ""
		if resp.StatusCode == http.StatusForbidden {
			hint = " (the anonymous API allows 60 requests an hour; `gh auth login` lifts that)"
		}
		return ghRelease{}, fmt.Errorf("asking GitHub about %s/%s: %s%s", owner, repo, resp.Status, hint)
	}
	var rel ghRelease
	if err := json.NewDecoder(resp.Body).Decode(&rel); err != nil {
		return ghRelease{}, fmt.Errorf("reading GitHub's answer for %s/%s: %w", owner, repo, err)
	}
	return rel, nil
}

func (f *Fetcher) ghBinary() string {
	switch f.GH {
	case "none":
		return ""
	case "":
		p, err := exec.LookPath("gh")
		if err != nil {
			return ""
		}
		return p
	}
	return f.GH
}

type ghRelease struct {
	TagName string    `json:"tag_name"`
	Assets  []ghAsset `json:"assets"`
}

type ghAsset struct {
	Name string `json:"name"`
	URL  string `json:"browser_download_url"`
	Size int64  `json:"size"`
}

// pickAsset chooses the asset a recipe asked for. With no pattern and exactly
// one APK in the release, that one; with a pattern, the match. Ambiguity is an
// error, not a guess: a release that ships app-full-release.apk beside
// app-minimal-release.apk has no obvious "the" APK.
func pickAsset(assets []ghAsset, pattern string) (ghAsset, error) {
	var apks, matched []ghAsset
	for _, a := range assets {
		if !strings.HasSuffix(strings.ToLower(a.Name), ".apk") {
			continue
		}
		apks = append(apks, a)
		if pattern != "" && globMatch(pattern, a.Name) {
			matched = append(matched, a)
		}
	}
	switch {
	case len(apks) == 0:
		return ghAsset{}, fmt.Errorf("the release has no .apk asset")
	case pattern == "" && len(apks) == 1:
		return apks[0], nil
	case pattern == "":
		return ghAsset{}, fmt.Errorf("the release has %d APKs (%s) and the recipe names no `asset:` pattern",
			len(apks), assetNames(apks))
	case len(matched) == 1:
		return matched[0], nil
	case len(matched) == 0:
		return ghAsset{}, fmt.Errorf("no asset matches %q (it has: %s)", pattern, assetNames(apks))
	}
	return ghAsset{}, fmt.Errorf("%d assets match %q (%s) — narrow the pattern", len(matched), pattern, assetNames(matched))
}

func assetNames(assets []ghAsset) string {
	var names []string
	for _, a := range assets {
		names = append(names, a.Name)
	}
	return strings.Join(names, ", ")
}

// globMatch is a '*' glob over a filename, which is all an asset pattern needs
// ("app-full-release.apk", "freekiosk-*.apk").
func globMatch(pattern, name string) bool {
	ok, err := filepath.Match(pattern, name)
	return err == nil && ok
}

// gitHubRepo reads a "github:owner/repo" source, or a github.com URL pointing
// at a repository or its releases page.
func gitHubRepo(source string) (owner, repo string, ok bool) {
	s := strings.TrimSpace(source)
	if rest, found := strings.CutPrefix(s, "github:"); found {
		return splitOwnerRepo(rest)
	}
	for _, prefix := range []string{"https://github.com/", "http://github.com/"} {
		if rest, found := strings.CutPrefix(s, prefix); found {
			return splitOwnerRepo(rest)
		}
	}
	return "", "", false
}

func splitOwnerRepo(s string) (string, string, bool) {
	parts := strings.Split(strings.Trim(s, "/"), "/")
	if len(parts) < 2 || parts[0] == "" || parts[1] == "" {
		return "", "", false
	}
	return parts[0], parts[1], true
}

func fileDigest(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// sanitizePathPart keeps a tag or asset name from escaping the cache directory.
func sanitizePathPart(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9',
			r == '.', r == '-', r == '_':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	out := strings.TrimLeft(b.String(), ".")
	if out == "" {
		return "apk"
	}
	return out
}
