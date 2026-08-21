//go:build nodonut

package services

import "fmt"

// ToShellcodeFromBytes is a no-op stub when -tags nodonut is set.
// Keeps unit-test binaries free of go-donut so AV is less likely to quarantine
// services.test.exe during `go test ./services`.
func ToShellcodeFromBytes(raw []byte, arch string) ([]byte, error) {
	_ = raw
	_ = arch
	return nil, fmt.Errorf("donut disabled (build with default tags for fileless/PIC conversion)")
}
