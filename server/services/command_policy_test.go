package services

import (
	"strings"
	"testing"
)

func TestConfirmDomainMatches(t *testing.T) {
	cases := []struct {
		confirm, domain string
		want            bool
	}{
		{"CORP.LOCAL", "corp.local", true},
		{"corp.local", "CORP.LOCAL", true},
		{"  corp.local ", "corp.local", true},
		{"corp.local", "other.local", false},
		{"", "corp.local", false},
		{"corp.local", "", false},
		{"", "", false},
	}
	for _, tc := range cases {
		got := ConfirmDomainMatches(tc.confirm, tc.domain)
		if got != tc.want {
			t.Errorf("ConfirmDomainMatches(%q,%q)=%v want %v", tc.confirm, tc.domain, got, tc.want)
		}
	}
}

func TestCheckHighRiskCommand_DcsyncPolicy(t *testing.T) {
	valid := `{"confirm":true,"confirm_domain":"corp.local","domain":"corp.local"}`
	validSpaced := `{
  "confirm": true,
  "confirm_domain": "Corp.Local",
  "domain": "corp.local"
}`
	// substring-style false positives must not pass: confirm is not boolean true
	falseConfirm := `{"confirm":false,"confirm_domain":"corp.local","domain":"corp.local"}`
	// malicious substring without real JSON true
	substringTrap := `{"note":"\"confirm\":true","confirm":false,"confirm_domain":"corp.local","domain":"corp.local"}`

	tests := []struct {
		name       string
		role       string
		isMCP      bool
		params     string
		wantErr    bool
		errContain string
	}{
		{"operator denied", "operator", false, valid, true, "access denied"},
		{"viewer denied", "viewer", false, valid, true, "access denied"},
		{"mcp denied even with admin-looking params", "mcp", true, valid, true, "mcp_high_risk_denied"},
		{"mcp role string denied", "mcp", false, valid, true, "mcp_high_risk_denied"},
		{"admin missing confirm", "admin", false, `{"domain":"corp.local","confirm_domain":"corp.local"}`, true, "confirm=true"},
		{"admin confirm false", "admin", false, falseConfirm, true, "confirm=true"},
		{"admin domain mismatch", "admin", false, `{"confirm":true,"confirm_domain":"other.local","domain":"corp.local"}`, true, "confirm_domain"},
		{"admin empty domain", "admin", false, `{"confirm":true,"confirm_domain":"corp.local","domain":""}`, true, "confirm_domain"},
		{"admin invalid json", "admin", false, `{not-json`, true, "invalid params"},
		{"admin empty params", "admin", false, "", true, "confirm=true"},
		{"admin substring trap", "admin", false, substringTrap, true, "confirm=true"},
		{"admin valid compact", "admin", false, valid, false, ""},
		{"admin valid spaced case", "admin", false, validSpaced, false, ""},
		{"administrator alias valid", "administrator", false, valid, false, ""},
		{"break-glass-admin alias valid", "break-glass-admin", false, valid, false, ""},
		// non-high-risk must pass regardless of role
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := CheckHighRiskCommand("dcsync", tc.role, tc.isMCP, tc.params)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tc.errContain)
				}
				if tc.errContain != "" && !strings.Contains(err.Error(), tc.errContain) {
					t.Fatalf("error %q does not contain %q", err.Error(), tc.errContain)
				}
				if !IsPolicyDenial(err) {
					t.Fatalf("IsPolicyDenial should be true for %v", err)
				}
			} else if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}

	// Low-risk AD op must not be gated
	if err := CheckHighRiskCommand("ad_discover", "operator", false, `{}`); err != nil {
		t.Fatalf("ad_discover should not be high-risk: %v", err)
	}
	if err := CheckHighRiskCommand("ad_ping", "viewer", false, `{}`); err != nil {
		t.Fatalf("ad_ping should not be high-risk: %v", err)
	}
	if IsHighRiskCommand("kerberoast") {
		t.Fatal("kerberoast is not high-risk in MVP gate table")
	}
	if !IsHighRiskCommand("dcsync") {
		t.Fatal("dcsync must be high-risk")
	}
}

func TestSendAdCommand_DcsyncGateBeforeOffline(t *testing.T) {
	// Policy must fail closed even when agent is offline — no bypass via missing client.
	valid := `{"confirm":true,"confirm_domain":"corp.local","domain":"corp.local"}`

	_, err := SendAdCommand("no-such-agent", "dcsync", valid, 0, "operator", false)
	if err == nil || !strings.Contains(err.Error(), "access denied") {
		t.Fatalf("operator dcsync want access denied, got %v", err)
	}

	_, err = SendAdCommand("no-such-agent", "dcsync", valid, 0, "admin", true)
	if err == nil || !strings.Contains(err.Error(), "mcp_high_risk_denied") {
		t.Fatalf("MCP dcsync want mcp_high_risk_denied, got %v", err)
	}

	_, err = SendAdCommand("no-such-agent", "dcsync", `{"confirm":true,"confirm_domain":"a","domain":"b"}`, 0, "admin", false)
	if err == nil || !strings.Contains(err.Error(), "confirm_domain") {
		t.Fatalf("mismatch confirm_domain want error, got %v", err)
	}

	// Admin + valid confirm: policy passes; offline is the next failure (proves gate allowed).
	_, err = SendAdCommand("no-such-agent", "dcsync", valid, 0, "admin", false)
	if err == nil {
		t.Fatal("expected agent offline after policy allow")
	}
	if strings.Contains(err.Error(), "access denied") || strings.Contains(err.Error(), "mcp_high_risk") {
		t.Fatalf("policy should have allowed admin+confirm, got %v", err)
	}
	if !strings.Contains(err.Error(), "agent offline") {
		t.Fatalf("want agent offline after allow, got %v", err)
	}

	// break-glass-admin must pass the same gate as admin (IsAdminRole alias).
	_, err = SendAdCommand("no-such-agent", "dcsync", valid, 0, "break-glass-admin", false)
	if err == nil {
		t.Fatal("expected agent offline after break-glass-admin allow")
	}
	if strings.Contains(err.Error(), "access denied") {
		t.Fatalf("break-glass-admin must not be denied dcsync policy: %v", err)
	}
	if !strings.Contains(err.Error(), "agent offline") {
		t.Fatalf("want agent offline after break-glass-admin allow, got %v", err)
	}

	// Non-high-risk op still reaches offline check for operator
	_, err = SendAdCommand("no-such-agent", "ad_ping", `{}`, 0, "operator", false)
	if err == nil || !strings.Contains(err.Error(), "agent offline") {
		t.Fatalf("ad_ping operator want offline, got %v", err)
	}
}
