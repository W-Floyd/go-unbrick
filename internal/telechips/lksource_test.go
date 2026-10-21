package telechips

import (
	"reflect"
	"testing"
)

const testProject = `TARGET := tcc897x-lcn
DEBUG := 1
#DEFINES += WITH_DEBUG_DCC=1
DEFINES += WITH_DEBUG_UART=1
ifeq ($(NAND_BOOT),1)
DEFINES += _NAND_BOOT=1
else
EMMC_BOOT := 1
ifeq ($(EMMC_BOOT),1)
DEFINES += _EMMC_BOOT=1
endif
endif
ifeq ($(HDEN),1)
HIDDEN_ENABLE := 1
endif
TZOW_ENABLE := 1
DEFINES += TSBM_ENABLE
#TCC_NSK_ENABLE := 1
`

const testRules = `PLATFORM := tcc897x
# 0x4210 : LCN   /TCC8971     /DDR3 1024MB(16bit*2) /TCC8971_LCN_CPU_MOD_4L_SV1.0
# 0x4211 : LCN   /TCC8972     /DDR3 1024MB(16bit*2) /TCC8972_LCN_CPU_MOD_4L_SV1.0
HW_REV=0x4210
`

func TestParseLKSource(t *testing.T) {
	s, ok := ParseLKSource([]byte(testProject), []byte(testRules))
	if !ok || s.Target != "tcc897x-lcn" || s.Platform != "tcc897x" || s.HWRev != "0x4210" {
		t.Fatalf("%+v", s)
	}
	if s.Board != "LCN   /TCC8971     /DDR3 1024MB(16bit*2) /TCC8971_LCN_CPU_MOD_4L_SV1.0" {
		t.Errorf("board %q", s.Board)
	}
	want := []string{"debug build", "UART debug output", "eMMC boot", "Telechips secure boot manager", "TrustZone OW"}
	if got := s.Describe(); !reflect.DeepEqual(got, want) {
		t.Errorf("describe %v", got)
	}
	for _, f := range s.Flags {
		if f == "_NAND_BOOT=1" || f == "HIDDEN_ENABLE=1" {
			t.Errorf("inactive branch taken: %s", f)
		}
	}
	if _, ok := ParseLKSource([]byte("DEBUG := 1"), nil); ok {
		t.Error("no TARGET accepted")
	}
}
