package bootimg

import (
	"bytes"
	"fmt"
	"path"
	"regexp"
	"sort"
	"strings"
)

// networkDaemons are programs whose presence in a root filesystem says it serves
// something to the network (and so something to look at first).
var networkDaemons = map[string]bool{
	"telnetd": true, "dropbear": true, "sshd": true, "ftpd": true, "tftpd": true, "httpd": true,
	"lighttpd": true, "nginx": true, "nfsd": true, "smbd": true, "adbd": true, "gdbserver": true,
	"dnsmasq": true, "avahi-daemon": true, "mosquitto": true, "vsftpd": true, "inetd": true, "udhcpd": true,
}

var busyboxVersion = regexp.MustCompile(`BusyBox v([0-9][0-9A-Za-z.\-_]*)`)

// DescribeRootfs summarises a root filesystem held as cpio entries (an initramfs): what
// is in it, what runs first, whom it lets in with what, what it serves to the network,
// and how much code it carries. Each line is a fact; nothing is guessed.
func DescribeRootfs(entries []CpioEntry) []string {
	var out []string
	files := map[string]CpioEntry{}
	var reg, dirs, links int
	var total int
	for _, e := range entries {
		if e.Name == "TRAILER!!!" {
			continue
		}
		name := strings.TrimPrefix(e.Name, "./")
		switch {
		case e.IsDir:
			dirs++
		case e.IsLink:
			links++
			files[name] = e
		default:
			reg++
			total += len(e.Data)
			files[name] = e
		}
	}
	out = append(out, fmt.Sprintf("Files: %d regular (%s), %d directories, %d links", reg, kib(total), dirs, links))

	for _, n := range []string{"init", "sbin/init", "linuxrc", "bin/init"} {
		e, ok := files[n]
		if !ok {
			continue
		}
		switch {
		case e.IsLink:
			out = append(out, fmt.Sprintf("Init: %s -> %s", n, e.LinkTo))
		case bytes.HasPrefix(e.Data, []byte("#!")):
			first, _, _ := bytes.Cut(e.Data, []byte("\n"))
			out = append(out, fmt.Sprintf("Init: %s, a script (%s), %d bytes", n, strings.TrimSpace(string(first)), len(e.Data)))
		case bytes.HasPrefix(e.Data, []byte("\x7fELF")):
			out = append(out, fmt.Sprintf("Init: %s, an ELF program, %s", n, kib(len(e.Data))))
		default:
			out = append(out, fmt.Sprintf("Init: %s, %s", n, kib(len(e.Data))))
		}
		break
	}

	for _, n := range []string{"etc/os-release", "usr/lib/os-release", "etc/issue"} {
		if e, ok := files[n]; ok && !e.IsLink {
			var keep []string
			for _, l := range strings.Split(string(e.Data), "\n") {
				l = strings.TrimSpace(l)
				if strings.HasPrefix(l, "PRETTY_NAME=") || strings.HasPrefix(l, "NAME=") || strings.HasPrefix(l, "VERSION=") || (n == "etc/issue" && l != "") {
					keep = append(keep, strings.Trim(strings.SplitN(l, "=", 2)[len(strings.SplitN(l, "=", 2))-1], `"`))
				}
			}
			if len(keep) > 0 {
				out = append(out, "OS: "+strings.Join(keep[:min(len(keep), 3)], ", ")+" ("+n+")")
				break
			}
		}
	}

	var scripts []string
	for n := range files {
		if strings.HasPrefix(n, "etc/init.d/") || n == "etc/inittab" || strings.HasPrefix(n, "etc/rc") && !strings.Contains(strings.TrimPrefix(n, "etc/"), "/") {
			scripts = append(scripts, n)
		}
	}
	sort.Strings(scripts)
	if len(scripts) > 0 {
		shown := scripts
		more := ""
		if len(shown) > 12 {
			shown, more = shown[:12], fmt.Sprintf(" (+%d more)", len(scripts)-12)
		}
		out = append(out, "Boot scripts: "+strings.Join(shown, ", ")+more)
	}

	if line := accountsLine(files); line != "" {
		out = append(out, line)
	}

	var daemons []string
	modules := 0
	var bb string
	for n, e := range files {
		base := path.Base(n)
		if networkDaemons[base] {
			daemons = append(daemons, n)
		}
		if strings.HasSuffix(n, ".ko") {
			modules++
		}
		if base == "busybox" && bb == "" && !e.IsLink {
			if m := busyboxVersion.FindSubmatch(e.Data); m != nil {
				bb = string(m[1])
			}
		}
	}
	sort.Strings(daemons)
	if len(daemons) > 0 {
		out = append(out, "Network services present: "+strings.Join(daemons, ", "))
	}
	if modules > 0 {
		out = append(out, fmt.Sprintf("Kernel modules: %d (*.ko)", modules))
	}
	if bb != "" {
		out = append(out, "BusyBox "+bb)
	}

	type sized struct {
		name string
		n    int
	}
	var big []sized
	for n, e := range files {
		if !e.IsLink {
			big = append(big, sized{n, len(e.Data)})
		}
	}
	sort.Slice(big, func(i, j int) bool {
		if big[i].n != big[j].n {
			return big[i].n > big[j].n
		}
		return big[i].name < big[j].name
	})
	var parts []string
	for _, b := range big[:min(len(big), 6)] {
		parts = append(parts, fmt.Sprintf("%s %s", b.name, kib(b.n)))
	}
	if len(parts) > 0 {
		out = append(out, "Largest: "+strings.Join(parts, ", "))
	}
	return out
}

// accountsLine says who the filesystem lets log in: the accounts /etc/passwd lists,
// those with a login shell, and those with no password at all, from /etc/shadow where
// there is one and the passwd field itself where there is not.
func accountsLine(files map[string]CpioEntry) string {
	p, ok := files["etc/passwd"]
	if !ok || p.IsLink {
		return ""
	}
	shadow := map[string]string{}
	if s, ok := files["etc/shadow"]; ok && !s.IsLink {
		for _, l := range strings.Split(string(s.Data), "\n") {
			if f := strings.Split(l, ":"); len(f) >= 2 {
				shadow[f[0]] = f[1]
			}
		}
	}
	var n, login int
	var empty []string
	for _, l := range strings.Split(string(p.Data), "\n") {
		f := strings.Split(strings.TrimSpace(l), ":")
		if len(f) < 7 {
			continue
		}
		n++
		hasShell := !strings.HasSuffix(f[6], "nologin") && !strings.HasSuffix(f[6], "/false") && f[6] != ""
		if hasShell {
			login++
		}
		pw := f[1]
		if pw == "x" {
			if h, ok := shadow[f[0]]; ok {
				pw = h
			}
		}
		if pw == "" && hasShell {
			empty = append(empty, f[0])
		}
	}
	line := fmt.Sprintf("Accounts: %d in /etc/passwd, %d with a login shell", n, login)
	if len(empty) > 0 {
		sort.Strings(empty)
		line += "; NO PASSWORD: " + strings.Join(empty, ", ")
	}
	return line
}
