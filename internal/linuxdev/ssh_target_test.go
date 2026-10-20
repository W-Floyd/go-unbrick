package linuxdev

import (
	osuser "os/user"
	"testing"
)

func TestSplitTargetDefaults(t *testing.T) {
	t.Setenv("HOME", t.TempDir()) // no ~/.ssh/config
	cur, err := osuser.Current()
	if err != nil {
		t.Skip(err)
	}
	user, host, port, _ := splitTarget("192.168.1.2", Options{})
	if user != cur.Username || host != "192.168.1.2" || port != "22" {
		t.Fatalf("got %q %q %q", user, host, port)
	}
	if user, _, _, _ := splitTarget("bob@h:2222", Options{}); user != "bob" {
		t.Fatalf("explicit user lost: %q", user)
	}
}
