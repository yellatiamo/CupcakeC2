package utils

import "testing"

func TestYamuxStreamTypeLockedValues(t *testing.T) {
	if YamuxStreamPTY != 0x01 {
		t.Fatalf("PTY: got 0x%02x want 0x01", YamuxStreamPTY)
	}
	if YamuxStreamSOCKS != 0x02 {
		t.Fatalf("SOCKS: got 0x%02x want 0x02", YamuxStreamSOCKS)
	}
	if YamuxStreamFS != 0x03 {
		t.Fatalf("FS: got 0x%02x want 0x03", YamuxStreamFS)
	}
	if YamuxStreamProcess != 0x04 {
		t.Fatalf("PROCESS: got 0x%02x want 0x04", YamuxStreamProcess)
	}
	if YamuxStreamFILE != 0x0E {
		t.Fatalf("FILE: got 0x%02x want 0x0E", YamuxStreamFILE)
	}
	if YamuxStreamReserved != 0xFF {
		t.Fatalf("RESERVED: got 0x%02x want 0xFF", YamuxStreamReserved)
	}
}

func TestYamuxStreamTypeTableMatchesConsts(t *testing.T) {
	want := map[string]byte{
		"PTY":      YamuxStreamPTY,
		"SOCKS":    YamuxStreamSOCKS,
		"FS":       YamuxStreamFS,
		"PROCESS":  YamuxStreamProcess,
		"FILE":     YamuxStreamFILE,
		"RESERVED": YamuxStreamReserved,
	}
	if len(YamuxStreamTypeTable) != len(want) {
		t.Fatalf("table len %d want %d", len(YamuxStreamTypeTable), len(want))
	}
	for _, e := range YamuxStreamTypeTable {
		v, ok := want[e.Name]
		if !ok {
			t.Fatalf("unexpected table name %q", e.Name)
		}
		if e.Value != v {
			t.Fatalf("%s: table 0x%02x != const 0x%02x", e.Name, e.Value, v)
		}
	}
}
