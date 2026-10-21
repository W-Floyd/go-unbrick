package bootimg

import (
	"strings"
	"testing"
)

func reg(name, data string) CpioEntry {
	return CpioEntry{Name: name, Data: []byte(data), Size: uint32(len(data)), IsReg: true}
}

func TestDescribeRootfs(t *testing.T) {
	entries := []CpioEntry{
		{Name: "bin", IsDir: true}, {Name: "etc", IsDir: true},
		{Name: "init", IsLink: true, LinkTo: "/sbin/init"},
		reg("sbin/init", "\x7fELFxxxx"),
		reg("etc/os-release", "NAME=\"Poky\"\nVERSION=\"3.1\"\nID=poky\n"),
		reg("etc/init.d/S10network", "#!/bin/sh\n"), reg("etc/init.d/S99app", "#!/bin/sh\n"),
		reg("etc/passwd", "root::0:0:root:/root:/bin/sh\ndaemon:x:1:1:d:/:/usr/sbin/nologin\nuser:x:1000:1000:u:/home/user:/bin/sh\n"),
		reg("etc/shadow", "root::0:0:::::\nuser:$6$salt$hash:0::::::\ndaemon:*:0::::::\n"),
		reg("usr/sbin/telnetd", "x"), reg("usr/sbin/dropbear", "x"),
		reg("lib/modules/4.14/a.ko", "m"), reg("lib/modules/4.14/b.ko", "m"),
		reg("bin/busybox", "xx BusyBox v1.31.1 (2023-01-06) multi-call binary"),
		{Name: "TRAILER!!!"},
	}
	got := strings.Join(DescribeRootfs(entries), "\n")
	for _, want := range []string{
		"Files: 11 regular", "2 directories", "1 links",
		"Init: init -> /sbin/init",
		"OS: Poky, 3.1 (etc/os-release)",
		"Boot scripts: etc/init.d/S10network, etc/init.d/S99app",
		"Accounts: 3 in /etc/passwd, 2 with a login shell; NO PASSWORD: root",
		"Network services present: usr/sbin/dropbear, usr/sbin/telnetd",
		"Kernel modules: 2",
		"BusyBox 1.31.1",
		"Largest:",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}
	// "user" has a hash in shadow, and "daemon" has no login shell: neither is listed
	// as having no password.
	if line := accountsLine(map[string]CpioEntry{
		"etc/passwd": reg("etc/passwd", "root::0:0:r:/root:/bin/sh\nuser:x:1:1:u:/h:/bin/sh\ndaemon::2:2:d:/:/sbin/nologin\n"),
		"etc/shadow": reg("etc/shadow", "user:$6$h:0::::::\n"),
	}); !strings.HasSuffix(line, "NO PASSWORD: root") {
		t.Errorf("accounts line: %q", line)
	}
}

func TestDescribeRootfsInitScriptAndNothing(t *testing.T) {
	got := strings.Join(DescribeRootfs([]CpioEntry{reg("init", "#!/bin/sh\nmount -t proc proc /proc\n")}), "\n")
	if !strings.Contains(got, "Init: init, a script (#!/bin/sh)") {
		t.Errorf("init script:\n%s", got)
	}
	if empty := DescribeRootfs(nil); len(empty) != 1 || !strings.HasPrefix(empty[0], "Files: 0 regular") {
		t.Errorf("empty: %v", empty)
	}
}
