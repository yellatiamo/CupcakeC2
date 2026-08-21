package services

import (
	"encoding/binary"
	"testing"
	"unicode/utf16"
)

func TestPackBofArgsWideDefaultDot(t *testing.T) {
	buf := packBofArgsWide("")
	if len(buf) < 4+4+2 {
		t.Fatalf("too short: %d", len(buf))
	}
	n := binary.BigEndian.Uint32(buf[:4])
	if n != 4 {
		t.Fatalf("len want 4 got %d", n)
	}
	// L"." = 2E 00 00 00
	if buf[4] != 0x2E || buf[5] != 0 || buf[6] != 0 || buf[7] != 0 {
		t.Fatalf("path bytes: %v", buf[4:8])
	}
	if binary.BigEndian.Uint16(buf[8:10]) != 0 {
		t.Fatalf("subdirs want 0")
	}
}

func TestPackBofArgsWidePathAndSlashS(t *testing.T) {
	buf := packBofArgsWide(`C:\Windows /s`)
	n := int(binary.BigEndian.Uint32(buf[:4]))
	units := utf16.Encode([]rune(`C:\Windows`))
	units = append(units, 0)
	want := len(units) * 2
	if n != want {
		t.Fatalf("path len want %d got %d", want, n)
	}
	if binary.BigEndian.Uint16(buf[4+n:4+n+2]) != 1 {
		t.Fatalf("subdirs want 1")
	}
	// round-trip first wchar
	if binary.LittleEndian.Uint16(buf[4:6]) != 'C' {
		t.Fatalf("first unit not C")
	}
}
