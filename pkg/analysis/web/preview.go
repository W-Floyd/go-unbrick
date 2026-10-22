package web

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/W-Floyd/go-unbrick/pkg/analysis"
)

// What both pages show of one file on its own: the browse page for any entry, the
// diff page for a file present on one side only. Same preview, same raw route.

// previewResp is what to show for an entry.
type previewResp struct {
	Entry     analysis.BrowseEntry     `json:"entry"`
	Kind      string                   `json:"kind"` // text, image, binary, dir
	Text      string                   `json:"text,omitempty"`
	HTML      string                   `json:"html,omitempty"` // Text, syntax-highlighted
	CanPretty bool                     `json:"canPretty"`      // the text can be shown reformatted
	Pretty    bool                     `json:"pretty"`         // ... and is
	Truncated bool                     `json:"truncated"`
	Strings   []string                 `json:"strings,omitempty"`  // for a binary: the printable strings in its start
	Entropy   *analysis.EntropyProfile `json:"entropy,omitempty"`  // for a binary: how random its start looks
	ByteHist  []int                    `json:"byteHist,omitempty"` // ... and its byte-value histogram
	Err       string                   `json:"err,omitempty"`
	Recon     *reconResp               `json:"recon,omitempty"`
}

type reconResp struct {
	State string `json:"state"` // running, done, failed
	Text  string `json:"text,omitempty"`
	Err   string `json:"err,omitempty"`
}

// maxPreviewStrings bounds the strings listed for a binary.
const maxPreviewStrings = 200

// buildPreview reads and classifies an entry for display: its text, highlighted
// (reformatted too, if it can be and raw is not asked for), an image to fetch from
// the raw route, or what it is.
func buildPreview(e analysis.BrowseEntry, raw bool, previewCap int64, redact func(string) string) previewResp {
	resp := previewResp{Entry: e, Kind: "binary"}
	switch {
	case e.Dir:
		resp.Kind = "dir"
	case e.Image:
		resp.Kind = "image"
	case e.Text:
		resp.Kind = "text"
		data, trunc, err := analysis.ReadEntry(e, previewCap)
		if err != nil {
			resp.Err = redact(err.Error())
			break
		}
		resp.Truncated = trunc
		show := data
		if pretty, ok := analysis.PrettyPrint(e.Name, data); ok {
			resp.CanPretty = true
			if !raw {
				show, resp.Pretty = pretty, true
			}
		}
		resp.Text = string(show)
		resp.HTML = highlightHTML(e.Name, show)
	}
	if resp.Kind == "binary" && (e.OSPath != "" || e.Node != nil) {
		if data, trunc, err := analysis.ReadEntry(e, previewCap); err == nil {
			resp.Truncated = trunc
			if len(data) >= 1024 {
				p := analysis.Entropy(data)
				resp.Entropy = &p
				resp.ByteHist = analysis.ByteHistogram(data)
			}
			for i, s := range analysis.Strings(data, 6) {
				if i >= maxPreviewStrings {
					break
				}
				resp.Strings = append(resp.Strings, s)
			}
		}
	}
	return resp
}

// serveRaw streams an entry: an image inline (capped), or any file as a download
// if the caller may.
func serveRaw(w http.ResponseWriter, r *http.Request, e analysis.BrowseEntry, imageCap int64, allowDownload func(*http.Request) bool, fail func(http.ResponseWriter, int, error)) {
	if e.Dir || (e.OSPath == "" && e.Node == nil) {
		fail(w, http.StatusBadRequest, errors.New("nothing to read"))
		return
	}
	download := r.URL.Query().Get("download") == "1"
	if download && allowDownload != nil && !allowDownload(r) {
		fail(w, http.StatusForbidden, errors.New("downloads are not allowed"))
		return
	}
	if !download && !e.Image {
		fail(w, http.StatusBadRequest, errors.New("not an image: use download=1"))
		return
	}
	rc, err := analysis.OpenEntryReader(e)
	if err != nil {
		fail(w, http.StatusInternalServerError, err)
		return
	}
	defer rc.Close()
	head := make([]byte, 512)
	n, _ := io.ReadFull(rc, head)
	head = head[:n]
	var body io.Reader = io.MultiReader(bytes.NewReader(head), rc)
	if download {
		w.Header().Set("Content-Type", "application/octet-stream")
		name := strings.ReplaceAll(strings.TrimSuffix(e.Name, "/"), `"`, "")
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, name))
		if e.Size >= 0 {
			w.Header().Set("Content-Length", fmt.Sprint(e.Size))
		}
	} else {
		w.Header().Set("Content-Type", http.DetectContentType(head))
		w.Header().Set("X-Content-Type-Options", "nosniff")
		body = io.LimitReader(body, imageCap)
	}
	io.Copy(w, body)
}
