package utils

import (
	"testing"
)

func TestWireIDsStableDefault(t *testing.T) {
	// Empty DefaultWireSeed maps to internal fallback; still must be stable.
	a := DeriveWireIDs("wire-internal-empty-fallback")
	b := DeriveWireIDs("wire-internal-empty-fallback")
	if a.PkgMagic != b.PkgMagic || a.FragMagic != b.FragMagic || a.JobMagic != b.JobMagic {
		t.Fatal("not stable")
	}
	if len(a.NoiseInfo) != 16 || len(a.ModKeyDomain) != 16 {
		t.Fatal("domain len")
	}
	if len(a.RegProofDomain) != 16 || len(a.NoiseInitDom) != 16 || len(a.NoiseRespDom) != 16 {
		t.Fatal("seed-derived domain len")
	}
	// Must not equal legacy ASCII brands
	if string(a.PkgMagic[:]) == "CKMS" {
		t.Fatal("still CKMS brand")
	}
	if string(a.FragMagic[:]) == "CKF1" {
		t.Fatal("still CKF1 brand")
	}
	if string(a.JobMagic[:]) == "CIS1" {
		t.Fatal("still CIS1 brand")
	}
}

func TestWireIDsDifferBySeed(t *testing.T) {
	a := DeriveWireIDs("seed-a")
	b := DeriveWireIDs("seed-b")
	if a.PkgMagic == b.PkgMagic {
		t.Fatal("different seeds must differ")
	}
	if string(a.RegProofDomain) == string(b.RegProofDomain) {
		t.Fatal("reg proof domain must differ by seed")
	}
}

func TestGenerateWireSeedNotPublicDefault(t *testing.T) {
	s := GenerateWireSeed()
	if s == "" || s == "wire-v1-default-2026" {
		t.Fatalf("generated seed looks like retired public default: %q", s)
	}
	if len(s) < 16 {
		t.Fatalf("seed too short: %q", s)
	}
}
