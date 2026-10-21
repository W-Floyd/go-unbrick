package telechips

import (
	"reflect"
	"testing"
)

func TestDefconfig(t *testing.T) {
	cfg := ParseDefconfig([]byte("CONFIG_ARM=y\nCONFIG_SYS_PROMPT=\"TCC # \"\n# CONFIG_X is not set\nCONFIG_FIT_SIGNATURE=y\nCONFIG_RSA=y\nCONFIG_USB_FUNCTION_FASTBOOT=y\nCONFIG_USB_STORAGE=n\n"))
	if cfg["CONFIG_SYS_PROMPT"] != "TCC # " || cfg["CONFIG_ARM"] != "y" {
		t.Errorf("%v", cfg)
	}
	want := []string{"FIT image signatures", "RSA verification", "USB fastboot"}
	if got := DescribeUBoot(cfg); !reflect.DeepEqual(got, want) {
		t.Errorf("describe %v", got)
	}
}
