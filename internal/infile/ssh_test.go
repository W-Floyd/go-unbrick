package infile

import (
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

// sftpServer serves SFTP for any login on a loopback listener and returns its
// host:port.
func sftpServer(t *testing.T) string {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &ssh.ServerConfig{NoClientAuth: true}
	cfg.AddHostKey(signer)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				_, chans, reqs, err := ssh.NewServerConn(c, cfg)
				if err != nil {
					return
				}
				go ssh.DiscardRequests(reqs)
				for nc := range chans {
					ch, creqs, err := nc.Accept()
					if err != nil {
						continue
					}
					go func() {
						for r := range creqs {
							ok := r.Type == "subsystem" && string(r.Payload[4:]) == "sftp"
							r.Reply(ok, nil)
							if ok {
								srv, _ := sftp.NewServer(ch)
								srv.Serve()
								ch.Close()
							}
						}
					}()
				}
			}()
		}
	}()
	return l.Addr().String()
}

func TestSSH(t *testing.T) {
	addr := sftpServer(t)
	SSHDial = func(target string) (*ssh.Client, error) {
		return ssh.Dial("tcp", addr, &ssh.ClientConfig{User: "u", HostKeyCallback: ssh.InsecureIgnoreHostKey()})
	}
	t.Cleanup(func() { SSHDial = nil; sshConns = map[string]*sshConn{} })
	sshConns = map[string]*sshConn{}

	dir := t.TempDir()
	body := make([]byte, 3<<20+17)
	for i := range body {
		body[i] = byte(i * 7)
	}
	os.MkdirAll(filepath.Join(dir, "sub", ".hid"), 0o755)
	os.WriteFile(filepath.Join(dir, "a.bin"), body, 0o644)
	os.WriteFile(filepath.Join(dir, "sub", "b.txt"), []byte("hi"), 0o644)
	os.WriteFile(filepath.Join(dir, "sub", ".hid", "c"), []byte("x"), 0o644)
	os.WriteFile(filepath.Join(dir, ".dot"), []byte("x"), 0o644)
	u := "ssh://me@host:22" + dir

	if !IsRemote(u) || !IsDir(u) || IsDir(u+"/a.bin") {
		t.Fatal("IsRemote/IsDir wrong")
	}
	f, err := Open(u + "/a.bin")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if f.Size() != int64(len(body)) || Base(u+"/a.bin") != "a.bin" {
		t.Fatalf("size %d base %s", f.Size(), Base(u+"/a.bin"))
	}
	got := make([]byte, 5000)
	off := int64(1<<20 - 100) // straddles a block boundary
	if _, err := f.ReadAt(got, off); err != nil || string(got) != string(body[off:off+5000]) {
		t.Fatalf("ReadAt: %v", err)
	}
	tail := make([]byte, 100)
	if n, err := f.ReadAt(tail, f.Size()-50); n != 50 || err == nil {
		t.Fatalf("tail read n=%d err=%v", n, err)
	}
	if _, err := Open(u); err == nil {
		t.Fatal("opening a directory should fail")
	}
	paths, err := WalkSSH(u)
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(paths)
	if len(paths) != 2 || !strings.HasSuffix(paths[0], "/a.bin") || !strings.HasSuffix(paths[1], "/sub/b.txt") {
		t.Fatalf("walk: %v", paths)
	}
	b, err := ReadFile(paths[1])
	if err != nil || string(b) != "hi" {
		t.Fatalf("ReadFile: %q %v", b, err)
	}
	es, err := ReadDir(u)
	if err != nil || len(es) != 3 {
		t.Fatalf("ReadDir: %v %v", es, err)
	}
	if j := Join(u, "sub"); j != u+"/sub" {
		t.Fatalf("Join: %s", j)
	}
}

func resetSSHFiles() {
	sshFiles.Range(func(k, _ any) bool { sshFiles.Delete(k); return true })
}

func TestSSHReadAheadWarmEvict(t *testing.T) {
	addr := sftpServer(t)
	SSHDial = func(target string) (*ssh.Client, error) {
		return ssh.Dial("tcp", addr, &ssh.ClientConfig{User: "u", HostKeyCallback: ssh.InsecureIgnoreHostKey()})
	}
	t.Cleanup(func() { SSHDial = nil; sshConns = map[string]*sshConn{}; resetSSHFiles() })
	sshConns = map[string]*sshConn{}
	resetSSHFiles()

	dir := t.TempDir()
	body := make([]byte, 20<<20+123)
	for i := range body {
		body[i] = byte(i * 11 >> 4)
	}
	os.WriteFile(filepath.Join(dir, "big.bin"), body, 0o644)
	u := "ssh://me@host" + dir + "/big.bin"

	var reads, bytes int64
	var mu sync.Mutex
	OnSSHRead = func(n int, _ time.Duration) { mu.Lock(); reads++; bytes += int64(n); mu.Unlock() }
	t.Cleanup(func() { OnSSHRead = nil })

	// Sequential read through a warmed file matches the source.
	Warm(u, 4<<20)
	f, err := Open(u)
	if err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(body))
	if _, err := io.ReadFull(f, got); err != nil {
		t.Fatal(err)
	}
	if !bytes_equal(got, body) {
		t.Fatal("sequential read differs")
	}
	// A second handle shares the same file; random reads across block edges.
	g, _ := Open(u)
	buf := make([]byte, 3000)
	for _, off := range []int64{0, 1<<20 - 1500, 7<<20 + 5, int64(len(body)) - 3000} {
		if _, err := g.ReadAt(buf, off); err != nil || !bytes_equal(buf, body[off:off+3000]) {
			t.Fatalf("ReadAt %d: %v", off, err)
		}
	}
	// Evict drops what was held; reading again still works.
	Evict(u)
	if _, err := g.ReadAt(buf, 5<<20); err != nil || !bytes_equal(buf, body[5<<20:5<<20+3000]) {
		t.Fatalf("after Evict: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if reads == 0 || bytes < int64(len(body)) {
		t.Fatalf("expected fetches of the whole file, got %d reads %d bytes", reads, bytes)
	}
}

func bytes_equal(a, b []byte) bool { return string(a) == string(b) }

// Reading a few bytes every megabyte (a tar's headers) fetches about a block
// per read, not the file; reading it through fetches it in few large requests.
func TestSSHStridedVersusSequential(t *testing.T) {
	addr := sftpServer(t)
	SSHDial = func(target string) (*ssh.Client, error) {
		return ssh.Dial("tcp", addr, &ssh.ClientConfig{User: "u", HostKeyCallback: ssh.InsecureIgnoreHostKey()})
	}
	t.Cleanup(func() { SSHDial = nil; sshConns = map[string]*sshConn{}; resetSSHFiles(); OnSSHRead = nil })
	sshConns = map[string]*sshConn{}
	resetSSHFiles()

	dir := t.TempDir()
	body := make([]byte, 40<<20)
	for i := range body {
		body[i] = byte(i * 7 >> 3)
	}
	os.WriteFile(filepath.Join(dir, "a.bin"), body, 0o644)
	os.WriteFile(filepath.Join(dir, "b.bin"), body, 0o644)

	var mu sync.Mutex
	var reads int
	var fetched int64
	OnSSHRead = func(n int, _ time.Duration) { mu.Lock(); reads++; fetched += int64(n); mu.Unlock() }
	snap := func() (int, int64) { mu.Lock(); defer mu.Unlock(); return reads, fetched }

	// A tar listing: the last byte of a member, then the next header, then a seek.
	f, _ := Open("ssh://me@host" + dir + "/a.bin")
	one, hdr := make([]byte, 1), make([]byte, 512)
	nreads := 0
	for off := int64(1<<20 - 1); off+512 < int64(len(body)); off += 1 << 20 {
		f.ReadAt(one, off)
		if _, err := f.ReadAt(hdr, off+1); err != nil || !bytes_equal(hdr, body[off+1:off+513]) {
			t.Fatalf("header at %d: %v", off, err)
		}
		nreads++
	}
	if _, got := snap(); got > int64(nreads)*2*blockSize {
		t.Errorf("strided reads fetched %d bytes for %d headers; want about a block each, not the file", got, nreads)
	}

	// Reading through is fetched in spans, far fewer requests than blocks.
	before, beforeBytes := snap()
	g, _ := Open("ssh://me@host" + dir + "/b.bin")
	buf := make([]byte, 32<<10)
	for off := int64(0); off < int64(len(body)); off += int64(len(buf)) {
		if _, err := g.ReadAt(buf, off); err != nil {
			t.Fatal(err)
		}
	}
	r, b := snap()
	if b-beforeBytes < int64(len(body)) {
		t.Errorf("sequential read fetched %d of %d bytes", b-beforeBytes, len(body))
	}
	if blocks := (len(body) + blockSize - 1) / blockSize; r-before > blocks/4 {
		t.Errorf("sequential read took %d requests for %d blocks; want spans", r-before, blocks)
	}
}
