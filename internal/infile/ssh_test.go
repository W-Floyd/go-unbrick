package infile

import (
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

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
