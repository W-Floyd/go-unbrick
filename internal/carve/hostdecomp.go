package carve

import (
	"bytes"
	"errors"
	"io"
	"os"
	"os/exec"
	"sync"
)

// HostDecomp lets decompression run through a faster tool already on the host
// (lbzip2, pbzip2, bzip2, pigz) in place of the pure-Go decoder, which is
// single-threaded and about half the speed of the C bzip2. Transparent: with no
// such tool, or UNBRICK_NO_HOST_DECOMP set, the Go decoder is used as before.
var HostDecomp = os.Getenv("UNBRICK_NO_HOST_DECOMP") == ""

// hostCodecs lists, per format, the tools to try in order of speed.
var hostCodecs = map[string][][]string{
	"bzip2": {{"lbzip2", "-dc"}, {"pbzip2", "-dc"}, {"bzip2", "-dc"}},
	"gzip":  {{"pigz", "-dc"}},
}

var (
	hostMu    sync.Mutex
	hostFound = map[string][]string{} // format -> argv, or nil when none is installed
)

func hostTool(format string) []string {
	hostMu.Lock()
	defer hostMu.Unlock()
	if argv, ok := hostFound[format]; ok {
		return argv
	}
	var found []string
	for _, c := range hostCodecs[format] {
		if p, err := exec.LookPath(c[0]); err == nil {
			found = append([]string{p}, c[1:]...)
			break
		}
	}
	hostFound[format] = found
	return found
}

// hostDecompress runs src through a host tool for format, or reports false when
// there is none and the caller should decode in Go. Closing the result stops
// the tool; src is the caller's to close.
func hostDecompress(format string, src io.Reader) (io.ReadCloser, bool) {
	if !HostDecomp {
		return nil, false
	}
	argv := hostTool(format)
	if argv == nil {
		return nil, false
	}
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Stdin = src
	var stderr bytes.Buffer
	cmd.Stderr = &limitedWriter{w: &stderr, n: 4096}
	out, err := cmd.StdoutPipe()
	if err != nil {
		return nil, false
	}
	if err := cmd.Start(); err != nil {
		return nil, false
	}
	return &hostReader{out: out, cmd: cmd, format: format, stderr: &stderr}, true
}

type hostReader struct {
	out    io.ReadCloser
	cmd    *exec.Cmd
	format string
	stderr *bytes.Buffer
	once   sync.Once
	werr   error
}

func (h *hostReader) wait() error {
	h.once.Do(func() { h.werr = h.cmd.Wait() })
	return h.werr
}

func (h *hostReader) Read(b []byte) (int, error) {
	k, err := h.out.Read(b)
	if err == io.EOF {
		// bzip2 exits 2 for trailing garbage after the stream too, which the
		// Go decoder ignores; only its message tells that from corruption.
		var ee *exec.ExitError
		trailing := h.format == "bzip2" && bytes.Contains(h.stderr.Bytes(), []byte("trailing garbage"))
		if werr := h.wait(); werr != nil && !(trailing && errors.As(werr, &ee) && ee.ExitCode() == 2) {
			return k, errors.New(h.cmd.Path + ": " + werr.Error() + ": " + string(bytes.TrimSpace(h.stderr.Bytes())))
		}
	}
	return k, err
}

func (h *hostReader) Close() error {
	h.once.Do(func() {
		h.cmd.Process.Kill()
		h.werr = h.cmd.Wait()
	})
	return nil
}

// limitedWriter keeps the first n bytes written, discarding the rest.
type limitedWriter struct {
	w io.Writer
	n int
}

func (l *limitedWriter) Write(p []byte) (int, error) {
	if l.n > 0 {
		k := min(len(p), l.n)
		l.w.Write(p[:k])
		l.n -= k
	}
	return len(p), nil
}

// closeBoth closes a decoder, then the source under it.
type closeBoth struct{ a, b io.Closer }

func (c closeBoth) Close() error {
	err := c.a.Close()
	if e := c.b.Close(); err == nil {
		err = e
	}
	return err
}

// hostMin is the compressed size below which starting a process costs more
// than the Go decoder takes.
const hostMin = 4 << 20

// useHost is hostDecompress for a member worth the process start: a small or
// unsized one stays in Go.
func useHost(format string, size int64, src io.Reader) (io.ReadCloser, bool) {
	if size < hostMin {
		return nil, false
	}
	return hostDecompress(format, src)
}
