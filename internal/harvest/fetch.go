package harvest

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/bzip2"
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/ulikunitz/xz"
)

// A loader or blankflash bundle is well under this (the largest legit dump is
// 70 MB); some "firehose" search hits are 10 GB+ ROMs.
const maxArchiveBytes = 300 << 20

const maxNestDepth = 3

const userAgent = "Mozilla/5.0"

var textClient = &http.Client{Timeout: 60 * time.Second}

// getText fetches a page as text, or "" on failure.
func getText(u string) string {
	req, err := http.NewRequest("GET", u, nil)
	if err != nil {
		return ""
	}
	req.Header.Set("User-Agent", userAgent)
	resp, err := textClient.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return ""
	}
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	return string(b)
}

var errTooLarge = errors.New("exceeds download cap")

// download streams u to local, capped at maxArchiveBytes; a partial file is
// removed on failure.
func download(u, local string) error {
	req, err := http.NewRequest("GET", u, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", userAgent)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	if resp.ContentLength > maxArchiveBytes {
		return errTooLarge
	}
	if err := os.MkdirAll(filepath.Dir(local), 0o755); err != nil {
		return err
	}
	f, err := os.Create(local)
	if err != nil {
		return err
	}
	n, err := io.Copy(f, io.LimitReader(resp.Body, maxArchiveBytes+1))
	f.Close()
	if err == nil && n > maxArchiveBytes {
		err = errTooLarge
	}
	if err != nil {
		os.Remove(local)
	}
	return err
}

var (
	reGDrive    = regexp.MustCompile(`drive\.google\.com/(?:file/d/|[^ ]*[?&]id=)([A-Za-z0-9_-]+)`)
	reMediafire = regexp.MustCompile(`mediafire\.com/file/([A-Za-z0-9]+)`)
	reMega      = regexp.MustCompile(`mega\.nz/(?:file/|#!)([A-Za-z0-9_-]+)`)
	reAFH       = regexp.MustCompile(`androidfilehost\.com/\?fid=([0-9]+)`)
	reStemJunk  = regexp.MustCompile(`[^A-Za-z0-9._-]`)
)

// resolveArchiveURL is (download URL, cache stem) for a source URL. Drive
// share links become their direct endpoint keyed by file id, so they do not all
// collapse onto one cache name; MediaFire, Mega and AFH resolve at fetch time.
func resolveArchiveURL(spec string) (string, string) {
	if m := reGDrive.FindStringSubmatch(spec); m != nil {
		// confirm=t skips the large-file virus-scan interstitial.
		return "https://drive.usercontent.google.com/download?id=" + m[1] + "&export=download&confirm=t", "gdrive_" + m[1]
	}
	if m := reMediafire.FindStringSubmatch(spec); m != nil {
		return spec, "mediafire_" + m[1]
	}
	if m := reMega.FindStringSubmatch(spec); m != nil {
		return spec, "mega_" + m[1]
	}
	if m := reAFH.FindStringSubmatch(spec); m != nil {
		return spec, "afh_" + m[1]
	}
	var segs []string
	for _, s := range strings.Split(strings.TrimRight(spec, "/"), "/") {
		if s != "" {
			segs = append(segs, s)
		}
	}
	stem := "download"
	if len(segs) > 0 {
		stem = segs[len(segs)-1]
	}
	return spec, reStemJunk.ReplaceAllString(stem, "_")
}

var reMediafireDirect = regexp.MustCompile(`https://download[0-9]+\.mediafire\.com/[^"'\s]+`)

// mediafireDirect is the direct URL behind a MediaFire /file/ page.
func mediafireDirect(page string) string {
	return reMediafireDirect.FindString(getText(page))
}

// afhDirect resolves an AndroidFileHost fid through its mirrors API; the URL
// carries an expiring token, so it is fetched fresh at download time.
func afhDirect(fid string) string {
	form := url.Values{"submit": {"true"}, "action": {"getdownloadmirrors"}, "fid": {fid}}
	req, err := http.NewRequest("POST", "https://androidfilehost.com/libs/otf/mirrors.otf.php",
		strings.NewReader(form.Encode()))
	if err != nil {
		return ""
	}
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-MOD-SBB-CTYPE", "xhr")
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	req.Header.Set("Referer", "https://androidfilehost.com/?fid="+fid)
	resp, err := textClient.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	var body struct {
		Mirrors []struct {
			URL string `json:"url"`
		} `json:"MIRRORS"`
	}
	if json.NewDecoder(resp.Body).Decode(&body) != nil || len(body.Mirrors) == 0 {
		return ""
	}
	return body.Mirrors[0].URL
}

// megaDownload fetches a Mega link (end-to-end encrypted; only MEGAcmd can)
// into local. mega-get names the file itself, so it lands in a temp dir.
func (h *harvester) megaDownload(u, local string) bool {
	if _, err := exec.LookPath("mega-get"); err != nil {
		h.errorf("mega link needs 'mega-get' (brew install --cask megacmd)")
		return false
	}
	tmp := strings.TrimSuffix(local, filepath.Ext(local)) + ".megatmp"
	os.RemoveAll(tmp)
	defer os.RemoveAll(tmp)
	_ = os.MkdirAll(tmp, 0o755)
	out, err := exec.Command("mega-get", u, tmp).CombinedOutput()
	var got string
	_ = filepath.WalkDir(tmp, func(p string, d os.DirEntry, e error) error {
		if e == nil && !d.IsDir() && got == "" {
			got = p
		}
		return nil
	})
	if err != nil || got == "" {
		h.errorf("mega-get failed: %.100s", strings.TrimSpace(string(out)))
		return false
	}
	return os.Rename(got, local) == nil
}

// fetchArchive downloads (if a URL) and extracts a loader archive, returning
// its extraction root, or "".
func (h *harvester) fetchArchive(spec string) string {
	archives := filepath.Join(h.o.CacheDir, "archives")
	var local string
	if strings.HasPrefix(spec, "http://") || strings.HasPrefix(spec, "https://") {
		u, stem := resolveArchiveURL(spec)
		local = filepath.Join(archives, stem+".archive")
		if _, err := os.Stat(local); err == nil && !h.o.Refresh {
			h.logf("  [cache] %s", spec)
		} else {
			h.logf("  [get] %s", spec)
			if !h.o.DryRun && !h.downloadSpec(spec, u, stem, local) {
				return ""
			}
		}
	} else {
		abs, err := filepath.Abs(spec)
		if err != nil {
			return ""
		}
		if _, err := os.Stat(abs); err != nil {
			h.errorf("no such archive: %s", spec)
			return ""
		}
		local = abs
	}

	stem := strings.TrimSuffix(filepath.Base(local), filepath.Ext(local))
	target := filepath.Join(archives, stem+".d")
	if _, err := os.Stat(target); err == nil && !h.o.Refresh {
		h.logf("  [cache] extracted at %s", target)
		return target
	}
	if h.o.DryRun {
		return target
	}
	// Extract into staging and promote only on success, so a .d's existence
	// guarantees a complete extraction.
	staging := filepath.Join(archives, stem+".d.partial")
	os.RemoveAll(staging)
	_ = os.MkdirAll(staging, 0o755)
	if !h.extractAny(local, staging) {
		os.RemoveAll(staging)
		return ""
	}
	// These dumps nest: gadgetsdr.com.rar is 237 files, 100 of them zips.
	for depth := 0; depth < maxNestDepth; depth++ {
		var nested []string
		_ = filepath.WalkDir(staging, func(p string, d os.DirEntry, e error) error {
			if e == nil && !d.IsDir() && archiveExts[strings.ToLower(filepath.Ext(p))] {
				nested = append(nested, p)
			}
			return nil
		})
		if len(nested) == 0 {
			break
		}
		h.logf("  [nested] depth %d: %d archive(s)", depth+1, len(nested))
		for _, q := range nested {
			sub := q + ".d"
			_ = os.MkdirAll(sub, 0o755)
			if h.extractAny(q, sub) {
				os.Remove(q) // only once its contents are out
			} else {
				h.warnf("kept %s: nested extraction failed", filepath.Base(q))
				os.RemoveAll(sub)
			}
		}
	}
	if h.o.Refresh {
		os.RemoveAll(target)
	}
	if err := os.Rename(staging, target); err != nil {
		h.errorf("promoting %s: %v", staging, err)
		return ""
	}
	return target
}

func (h *harvester) downloadSpec(spec, u, stem, local string) bool {
	switch {
	case strings.HasPrefix(stem, "mega_"):
		return h.megaDownload(u, local)
	case strings.HasPrefix(stem, "afh_"):
		u = afhDirect(strings.TrimPrefix(stem, "afh_"))
		if u == "" {
			h.errorf("AFH download failed for %s", spec)
			return false
		}
	case strings.HasPrefix(stem, "mediafire_"):
		if u = mediafireDirect(u); u == "" {
			h.errorf("could not resolve MediaFire link %s", spec)
			return false
		}
	}
	if err := download(u, local); err != nil {
		h.errorf("failed to download %s: %v", spec, err)
		return false
	}
	return true
}

// extractAny extracts one archive into target: zip and tar (plain, gzip,
// bzip2, xz) natively, everything else — RAR5, 7z, encrypted zips — via unar.
// Dispatch is on leading magic, since whole-file sniffing false-positives on a
// container that embeds a zip (a RAR full of .zip loaders).
func (h *harvester) extractAny(local, target string) bool {
	head, err := readHead(local, 8)
	if err != nil {
		h.errorf("reading %s: %v", filepath.Base(local), err)
		return false
	}
	isZip := bytes.HasPrefix(head, []byte("PK\x03\x04")) || bytes.HasPrefix(head, []byte("PK\x05\x06")) ||
		bytes.HasPrefix(head, []byte("PK\x07\x08"))
	isUnar := bytes.HasPrefix(head, []byte("Rar!\x1a\x07")) || bytes.HasPrefix(head, []byte("7z\xbc\xaf\x27\x1c"))
	switch {
	case isZip:
		if err := extractZip(local, target, h.o.ArchivePassword != ""); err == nil {
			return true
		} else if !errors.Is(err, errNeedsUnar) {
			h.errorf("extracting %s: %v", filepath.Base(local), err)
			return false
		}
	case !isUnar:
		if err := extractTar(local, target, head); err == nil {
			return true
		}
	}
	return h.unar(local, target)
}

var errNeedsUnar = errors.New("encrypted zip")

func extractZip(local, target string, havePassword bool) error {
	z, err := zip.OpenReader(local)
	if err != nil {
		return err
	}
	defer z.Close()
	for _, f := range z.File {
		if f.Flags&0x1 != 0 {
			if havePassword {
				return errNeedsUnar
			}
			continue
		}
		if err := writeMember(target, f.Name, f.FileInfo().IsDir(), func() (io.ReadCloser, error) { return f.Open() }); err != nil {
			return err
		}
	}
	return nil
}

func extractTar(local, target string, head []byte) error {
	f, err := os.Open(local)
	if err != nil {
		return err
	}
	defer f.Close()
	var r io.Reader = f
	switch {
	case bytes.HasPrefix(head, []byte("\x1f\x8b")):
		gz, err := gzip.NewReader(f)
		if err != nil {
			return err
		}
		r = gz
	case bytes.HasPrefix(head, []byte("BZh")):
		r = bzip2.NewReader(f)
	case bytes.HasPrefix(head, []byte("\xfd7zXZ\x00")):
		x, err := xz.NewReader(f)
		if err != nil {
			return err
		}
		r = x
	}
	tr := tar.NewReader(r)
	n := 0
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		if hdr.Typeflag != tar.TypeReg && hdr.Typeflag != tar.TypeDir {
			continue // no links or devices out of a scraped archive
		}
		if err := writeMember(target, hdr.Name, hdr.Typeflag == tar.TypeDir,
			func() (io.ReadCloser, error) { return io.NopCloser(tr), nil }); err != nil {
			return err
		}
		n++
	}
	if n == 0 {
		return errors.New("not a tar archive")
	}
	return nil
}

// writeMember writes one archive member under target, refusing absolute paths
// and traversal.
func writeMember(target, name string, dir bool, open func() (io.ReadCloser, error)) error {
	clean := filepath.Clean(filepath.FromSlash(name))
	if filepath.IsAbs(clean) || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return nil
	}
	dst := filepath.Join(target, clean)
	if dir {
		return os.MkdirAll(dst, 0o755)
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	rc, err := open()
	if err != nil {
		return err
	}
	defer rc.Close()
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	_, err = io.Copy(out, rc)
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	return err
}

// unar handles what the standard library cannot: RAR5 (7-Zip cannot decode
// method v6, libarchive rejects its block headers), 7z and encrypted zips.
func (h *harvester) unar(local, target string) bool {
	if _, err := exec.LookPath("unar"); err != nil {
		h.errorf("%s needs 'unar' (brew install unar)", filepath.Base(local))
		return false
	}
	args := []string{"-q", "-D", "-o", target}
	if h.o.ArchivePassword != "" {
		args = append(args, "-p", h.o.ArchivePassword)
	}
	out, err := exec.Command("unar", append(args, local)...).CombinedOutput()
	if err != nil || strings.Contains(string(out), "wrong password") {
		h.errorf("unar failed on %s: %.120s", filepath.Base(local), strings.TrimSpace(string(out)))
		return false
	}
	return true
}
