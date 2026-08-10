package services

import (
	"strings"
	"testing"
)

func TestMCPConfirmRequired_AllWrites(t *testing.T) {
	if MCPConfirmRequired("GET", "/api/ad/tasks") {
		t.Fatal("GET must not require confirm")
	}
	if MCPConfirmRequired("HEAD", "/api/clients") {
		t.Fatal("HEAD must not require confirm")
	}
	// Every mutation requires confirm — including low-risk AD ping
	for _, tc := range []struct{ m, p string }{
		{"POST", "/api/cmd"},
		{"POST", "/api/ad/ping"},
		{"POST", "/api/ad/discover"},
		{"POST", "/api/ad/exec"},
		{"POST", "/api/modules/push"},
		{"DELETE", "/api/modules/ad"},
		{"POST", "/api/files/delete"},
		{"POST", "/api/processes/kill"},
		{"POST", "/api/plugins/run"},
		{"POST", "/api/tunnel/start"},
	} {
		if !MCPConfirmRequired(tc.m, tc.p) {
			t.Fatalf("%s %s must require confirm", tc.m, tc.p)
		}
	}
}

func TestBuildMCPSummary_ShellIncludesFullCommand(t *testing.T) {
	sum, risk, op, agent := BuildMCPSummary("POST", "/api/cmd",
		`{"uuid":"agent-1","cmd":"whoami /all && net user","purpose":"确认当前登录身份与本机用户列表"}`)
	if risk != "high" {
		t.Fatalf("risk=%s", risk)
	}
	if op != "shell" {
		t.Fatalf("op=%s", op)
	}
	if agent != "agent-1" {
		t.Fatalf("agent=%s", agent)
	}
	if !strings.Contains(sum, "whoami /all && net user") {
		t.Fatalf("summary must include full shell command, got: %s", sum)
	}
	if !strings.Contains(sum, "【Shell】") {
		t.Fatalf("summary should label Shell: %s", sum)
	}
	if !strings.Contains(sum, "用途:") || !strings.Contains(sum, "确认当前登录身份") {
		t.Fatalf("summary must include model purpose, got: %s", sum)
	}
}

func TestBuildMCPSummary_AdDiscover(t *testing.T) {
	sum, risk, op, _ := BuildMCPSummary("POST", "/api/ad/exec",
		`{"uuid":"u1","op":"ad_discover","params":{"domain":"ceshi.c2"}}`)
	if op != "ad_discover" {
		t.Fatalf("op=%s", op)
	}
	if risk != "low" {
		t.Fatalf("risk=%s want low", risk)
	}
	if !strings.Contains(sum, "ceshi.c2") && !strings.Contains(sum, "ad_discover") {
		t.Fatalf("summary incomplete: %s", sum)
	}
}
