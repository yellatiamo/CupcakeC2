package services

import "testing"

func TestValidateTunnelPort(t *testing.T) {
	cases := []struct {
		in      string
		want    string
		wantErr bool
	}{
		{"", "", true},
		{"   ", "", true},
		{"0", "", true},
		{"-1", "", true},
		{"65536", "", true},
		{"abc", "", true},
		{"1080", "1080", false},
		{" 22 ", "22", false},
		{"080", "80", false},
	}
	for _, tc := range cases {
		got, err := ValidateTunnelPort(tc.in)
		if tc.wantErr {
			if err == nil {
				t.Errorf("ValidateTunnelPort(%q) err=nil want error", tc.in)
			}
			continue
		}
		if err != nil {
			t.Errorf("ValidateTunnelPort(%q) err=%v", tc.in, err)
			continue
		}
		if got != tc.want {
			t.Errorf("ValidateTunnelPort(%q)=%q want %q", tc.in, got, tc.want)
		}
	}
}

func TestAgentIsOnlineEmpty(t *testing.T) {
	if AgentIsOnline("") {
		t.Fatal("empty uuid must be offline")
	}
	if AgentIsOnline("no-such-agent-uuid-xyz") {
		t.Fatal("unknown agent must be offline")
	}
}
