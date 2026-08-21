//go:build !nodonut

package services

import (
	"bytes"
	"fmt"

	"github.com/Binject/go-donut/donut"
)

// ToShellcodeFromBytes converts raw PE bytes to PIC shellcode using Donut.
// Omitted from the package when building with -tags nodonut (safe unit tests).
func ToShellcodeFromBytes(raw []byte, arch string) ([]byte, error) {
	donutArch := donut.X64
	if arch == "i386" || arch == "x86" || arch == "386" {
		donutArch = donut.X32
	}

	config := &donut.DonutConfig{
		Arch:       donutArch,
		Type:       donut.DONUT_MODULE_EXE,
		InstType:   donut.DONUT_INSTANCE_PIC,
		Entropy:    donut.DONUT_ENTROPY_NONE,
		Class:      "",
		Method:     "",
		Parameters: "",
		Verbose:    false,
		// Bypass=1: DONUT_OPT_BYPASS_NONE — avoid AMSI/ETW patching that trips CFG.
		Bypass: 1,
		// Thread=0: run in current thread; agent loader creates the thread.
		Thread: 0,
	}

	payload, err := donut.ShellcodeFromBytes(bytes.NewBuffer(raw), config)
	if err != nil {
		return nil, fmt.Errorf("donut conversion failed: %v", err)
	}

	return payload.Bytes(), nil
}
