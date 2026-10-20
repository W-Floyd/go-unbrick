package infile

import (
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

// SSHDial connects to "user@host[:port]". It is set by the command layer, which
// owns authentication and host-key policy; infile only speaks SFTP over it.
var SSHDial func(target string) (*ssh.Client, error)

// OnSSHRead, when set, is told of each block fetched over SFTP: its bytes and
// how long the round trip took. For profiling.
var OnSSHRead func(n int, d time.Duration)

// IsSSH reports whether p is an ssh://[user@]host[:port]/path URL, read over SFTP.
func IsSSH(p string) bool { return strings.HasPrefix(p, "ssh://") }

type sshConn struct {
	cl  *sftp.Client
	err error
}

var (
	sshMu    sync.Mutex
	sshConns = map[string]*sshConn{}
)

// splitSSH returns the dial target and absolute remote path of an ssh:// URL.
func splitSSH(p string) (target, remote string, err error) {
	u, err := url.Parse(p)
	if err != nil {
		return "", "", err
	}
	if u.Host == "" {
		return "", "", fmt.Errorf("%s: no host", p)
	}
	target = u.Host
	if u.User != nil {
		target = u.User.Username() + "@" + target
	}
	remote = u.Path
	if remote == "" {
		remote = "/"
	}
	return target, remote, nil
}

// sshURL rebuilds the URL for remote path rp on the same host as base.
func sshURL(base, rp string) string {
	u, _ := url.Parse(base)
	u.Path, u.RawPath = rp, ""
	return u.String()
}

// sftpFor returns the shared SFTP client for p's host, dialing on first use.
func sftpFor(p string) (*sftp.Client, string, error) {
	target, remote, err := splitSSH(p)
	if err != nil {
		return nil, "", err
	}
	sshMu.Lock()
	defer sshMu.Unlock()
	c, ok := sshConns[target]
	if !ok {
		c = &sshConn{}
		if SSHDial == nil {
			c.err = fmt.Errorf("ssh inputs are not available here")
		} else if conn, err := SSHDial(target); err != nil {
			c.err = err
		} else if c.cl, err = sftp.NewClient(conn, sftp.UseConcurrentReads(true)); err != nil {
			conn.Close()
			c.err = fmt.Errorf("sftp on %s: %w", target, err)
		}
		sshConns[target] = c
	}
	return c.cl, remote, c.err
}

func statSSH(p string) (fs.FileInfo, error) {
	cl, rp, err := sftpFor(p)
	if err != nil {
		return nil, err
	}
	return cl.Stat(rp)
}

// IsDir reports whether p names a directory: a local one, or an ssh:// one. An
// http URL never is.
func IsDir(p string) bool {
	if IsSSH(p) {
		fi, err := statSSH(p)
		return err == nil && fi.IsDir()
	}
	if IsRemote(p) {
		return false
	}
	fi, err := Stat(p)
	return err == nil && fi.IsDir()
}

// WalkSSH lists the regular files under an ssh:// directory as URLs, skipping
// dot-files and dot-directories as a local directory recon does. Symlinks to
// files are followed; symlinks to directories are not, so a loop cannot trap it.
func WalkSSH(root string) ([]string, error) {
	cl, rp, err := sftpFor(root)
	if err != nil {
		return nil, err
	}
	var out []string
	w := cl.Walk(rp)
	for w.Step() {
		if err := w.Err(); err != nil {
			return nil, err
		}
		fi := w.Stat()
		if w.Path() != rp && strings.HasPrefix(path.Base(w.Path()), ".") {
			if fi.IsDir() {
				w.SkipDir()
			}
			continue
		}
		if fi.Mode()&fs.ModeSymlink != 0 {
			if t, err := cl.Stat(w.Path()); err == nil {
				fi = t
			}
		}
		if fi.Mode().IsRegular() {
			out = append(out, sshURL(root, w.Path()))
		}
	}
	return out, nil
}

// ReadDir is os.ReadDir for a local directory or an ssh:// one. Symlinks to
// directories are reported as directories.
func ReadDir(dir string) ([]fs.DirEntry, error) {
	if !IsSSH(dir) {
		return os.ReadDir(dir)
	}
	cl, rp, err := sftpFor(dir)
	if err != nil {
		return nil, err
	}
	infos, err := cl.ReadDir(rp)
	if err != nil {
		return nil, err
	}
	out := make([]fs.DirEntry, 0, len(infos))
	for _, fi := range infos {
		if fi.Mode()&fs.ModeSymlink != 0 {
			if t, err := cl.Stat(path.Join(rp, fi.Name())); err == nil {
				fi = t
			}
		}
		out = append(out, fs.FileInfoToDirEntry(fi))
	}
	return out, nil
}

// Join is filepath.Join for a directory and an entry in it, ssh:// included.
func Join(dir, name string) string {
	if !IsSSH(dir) {
		return filepath.Join(dir, name)
	}
	u, err := url.Parse(dir)
	if err != nil {
		return dir + "/" + name
	}
	return sshURL(dir, path.Join(u.Path, name))
}

// Identity names p's current content for caching: its location plus whatever
// changes when the bytes do (size and mtime; an http object's ETag or
// Last-Modified). "" when it cannot be determined, which disables caching.
func Identity(p string) string {
	switch {
	case isHTTP(p):
		r, err := openRemote(p)
		if err != nil {
			return ""
		}
		return fmt.Sprintf("%s|%d|%s|%s", r.meta.URL, r.size, r.meta.ETag, r.meta.LastModified)
	case IsSSH(p):
		fi, err := statSSH(p)
		if err != nil {
			return ""
		}
		return fmt.Sprintf("%s|%d|%d", p, fi.Size(), fi.ModTime().UnixNano())
	}
	abs, err := filepath.Abs(p)
	if err != nil {
		return ""
	}
	fi, err := os.Stat(abs)
	if err != nil {
		return ""
	}
	return fmt.Sprintf("%s|%d|%d", abs, fi.Size(), fi.ModTime().UnixNano())
}
