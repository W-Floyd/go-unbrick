package unixauth

import "testing"

func TestClassify(t *testing.T) {
	cases := map[string]Scheme{
		"":                                   SchemeNone,
		"*":                                  SchemeLocked,
		"!":                                  SchemeLocked,
		"!!":                                 SchemeLocked,
		"x":                                  SchemeLocked,
		"TOG3DLSQdFPY.":                      SchemeDES,
		"$1$abcdefgh$xxxxxxxxxxxxxxxxxxxxxx": SchemeMD5,
		"$6$abcdefgh$xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx": SchemeSHA512,
		"$2b$10$abcdefghijklmnopqrstuv": SchemeBlowfish,
		"!$6$abcdefgh$xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx": SchemeSHA512, // locked, scheme still visible
		"!justjunk": SchemeLocked,
	}
	for hash, want := range cases {
		if got := classify(hash); got != want {
			t.Errorf("classify(%q) = %q, want %q", hash, got, want)
		}
	}
}

func TestWeak(t *testing.T) {
	if !SchemeDES.Weak() || !SchemeMD5.Weak() {
		t.Error("DES and MD5 crypt should be weak")
	}
	if SchemeSHA512.Weak() || SchemeBlowfish.Weak() || SchemeYescrypt.Weak() {
		t.Error("a modern KDF scheme should not be weak")
	}
}

func TestParseShadowAndFingerprint(t *testing.T) {
	data := []byte("root:TOG3DLSQdFPY.:19290:0:99999:7:::\ndaemon:*:19290:0:99999:7:::\n# comment\n\nbad line\n")
	es := ParseShadow(data)
	if len(es) != 2 {
		t.Fatalf("got %d entries: %+v", len(es), es)
	}
	root, daemon := es[0], es[1]
	if root.User != "root" || root.Scheme != SchemeDES || !root.HasPassword() {
		t.Errorf("root: %+v", root)
	}
	if daemon.User != "daemon" || daemon.Scheme != SchemeLocked || daemon.HasPassword() {
		t.Errorf("daemon: %+v", daemon)
	}
	if daemon.Fingerprint() != "" {
		t.Error("a locked account has no fingerprint")
	}
	if root.Fingerprint() == "" || len(root.Fingerprint()) != 12 {
		t.Errorf("fingerprint %q", root.Fingerprint())
	}
	// Same hash, same fingerprint; the raw value never needs comparing directly.
	other := ParseShadow([]byte("root:TOG3DLSQdFPY.:19172:0:99999:7:::\n"))[0]
	if other.Fingerprint() != root.Fingerprint() {
		t.Error("identical hashes should fingerprint identically regardless of other fields")
	}
	diff := ParseShadow([]byte("root:xxxxxxxxxxxxx:19290:0:99999:7:::\n"))[0]
	if diff.Fingerprint() == root.Fingerprint() {
		t.Error("different hashes should not collide")
	}
}

func TestParsePasswd(t *testing.T) {
	data := []byte("root:x:0:0:root:/root:/bin/sh\nnobody:x:65534:65534::/:/sbin/nologin\n")
	ps := ParsePasswd(data)
	if len(ps) != 2 || ps[0].User != "root" || ps[0].UID != 0 || ps[1].Shell != "/sbin/nologin" {
		t.Errorf("%+v", ps)
	}
}

func TestParsePPPSecrets(t *testing.T) {
	data := []byte("# comment\nclientA serverB secretB *\nclientC * secretD 10.0.0.1\n")
	ss := ParsePPPSecrets(data)
	if len(ss) != 2 {
		t.Fatalf("%+v", ss)
	}
	if ss[0].Client != "clientA" || ss[0].Server != "serverB" || ss[0].Secret != "secretB" || ss[0].IPs != "*" {
		t.Errorf("%+v", ss[0])
	}
	if ss[1].IPs != "10.0.0.1" {
		t.Errorf("%+v", ss[1])
	}
	if ss[0].Fingerprint() == "" {
		t.Error("a real secret should fingerprint")
	}
	wild := ParsePPPSecrets([]byte("c s * *\n"))[0]
	if wild.Fingerprint() != "" {
		t.Error("a wildcard secret ('*') carries nothing to compare")
	}
}
