package telechips

import (
	"reflect"
	"testing"
)

// The default environment of a real head unit's BL3 (an MS400 TCC803x OTA).
var ms400Env = map[string]string{
	"bootpart": "boot", "fdtpart": "dtb", "miscpart": "misc",
	"avb_verify":  "avb init ${bootdev} ${bootdevnum}; avb verify ${slot};",
	"loadfdtpart": "fdt load - ${bootdevnum}#${fdtpart} ${slot} ${fdt_addr}; if test $? -ne 0; then echo Error loading a device tree blob; exit; fi",
	"bootcmd": "smc reset_type rst_type; if test ${rst_type} = cold; then " +
		"fdt load - ${bootdevnum}#a7s_dtb ${slot} ${subcore_fdt_addr}; " +
		"tcc_load part - ${bootdevnum}#a7s_boot ${slot} ${subcore_kerneladdr} - - sc_kernel_size; " +
		"tcc_load part - ${bootdevnum}#a7s_root ${slot} ${subcore_root_addr} - - sc_root_size; " +
		"avm_start 0; avm_start 1; fi; run loadfdtpart; fdt addr ${fdt_addr}; " +
		"dtimg load - 0#dtbo ${slot} ${overlay_addr}; dtimg index ${overlay_addr} ${board_id} - dtbo_index; " +
		"fdt apply ${dtbo_addr}; fdt optee; " +
		"if run avb_verify; then echo AVB verification OK.;setenv android_rootdev;else echo AVB verification failed.;exit;fi;" +
		"boot_android - ${bootdevnum}#${miscpart} ${slot} ${kerneladdr}",
}

func TestBootLoads(t *testing.T) {
	loads, verifies := BootLoads(ms400Env)
	if !verifies {
		t.Error("the script runs avb verify")
	}
	want := []PartitionLoad{
		{"a7s_dtb", "fdt load", true},
		{"a7s_boot", "tcc_load part", true},
		{"a7s_root", "tcc_load part", true},
		{"dtb", "fdt load", true}, // through `run loadfdtpart`, with ${fdtpart} expanded
		{"dtbo", "dtimg load", true},
		{"boot", "boot_android", false}, // its control data is misc; what it boots is boot
	}
	if !reflect.DeepEqual(loads, want) {
		t.Errorf("loads:\n got %+v\nwant %+v", loads, want)
	}
}

func TestBootLoadsWithoutAVBOrScript(t *testing.T) {
	loads, verifies := BootLoads(map[string]string{"bootcmd": "mmc read 0x1000 0 1; fdt load - 0#dtb a 0x2000; ab select slot - 0#misc"})
	if verifies {
		t.Error("no avb verify in this script")
	}
	if len(loads) != 1 || loads[0].Partition != "dtb" || loads[0].BeforeAVB {
		t.Errorf("loads: %+v", loads)
	}
	if loads, v := BootLoads(nil); loads != nil || v {
		t.Errorf("no environment: %+v %v", loads, v)
	}
}
