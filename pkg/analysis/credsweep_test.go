package analysis

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSweepCredsFindsSharedAndWeak(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string) {
		p := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// Two variants sharing a root password (the finding), one with a different one.
	write("a/etc/shadow", "root:TOG3DLSQdFPY.:19290:0:99999:7:::\ndaemon:*:1:0:9:7:::\n")
	write("b/etc/shadow", "root:TOG3DLSQdFPY.:19172:0:99999:7:::\n")
	write("c/etc/shadow", "root:$6$abcdefgh$xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx:1:0:9:7:::\n")
	write("a/etc/ppp/chap-secrets", "unit server fixedsecret *\n")
	write("b/etc/ppp/chap-secrets", "unit server fixedsecret *\n")
	write("skip/etc/shadow", "root:shouldnotappear1:1:0:9:7:::\n")

	res, err := SweepCreds(context.Background(), dir, CredSweepOptions{Skip: []string{`(^|/)skip/`}})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Accounts) != 4 { // a's root+daemon, b's root, c's root — "daemon" is locked but still a row
		t.Fatalf("accounts: %+v", res.Accounts)
	}
	if res.Files != 5 { // 3 shadow files + 2 chap-secrets files; skip/etc/shadow is excluded
		t.Errorf("files = %d", res.Files)
	}
	if len(res.SharedAccounts) != 1 {
		t.Fatalf("shared accounts: %+v", res.SharedAccounts)
	}
	for _, group := range res.SharedAccounts {
		if len(group) != 2 {
			t.Errorf("shared group size %d: %+v", len(group), group)
		}
	}
	if len(res.SharedSecrets) != 1 {
		t.Fatalf("shared secrets: %+v", res.SharedSecrets)
	}

	summary := res.Summary()
	for _, bad := range []string{"TOG3DLSQdFPY.", "fixedsecret", "shouldnotappear1"} {
		if strings.Contains(summary, bad) {
			t.Errorf("summary leaked a raw secret %q:\n%s", bad, summary)
		}
	}
	for _, want := range []string{"weak", "shared across more than one file"} {
		if !strings.Contains(summary, want) {
			t.Errorf("summary missing %q:\n%s", want, summary)
		}
	}
}
