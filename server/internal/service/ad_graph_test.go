package services

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func sampleGraph() *CupcakeGraph {
	return &CupcakeGraph{
		Format: "cupcake-graph-v1",
		Domain: "corp.local",
		Nodes: []CupcakeNode{
			{ID: "DOMAIN:corp.local", Kind: "Domain", Name: "corp.local"},
			{ID: "COMPUTER:dc01.corp.local", Kind: "Computer", Name: "dc01.corp.local"},
			{ID: "GROUP:Domain Admins", Kind: "Group", Name: "Domain Admins"},
			{ID: "USER:alice", Kind: "User", Name: "alice"},
		},
		Edges: []CupcakeEdge{
			{Source: "DOMAIN:corp.local", Target: "COMPUTER:dc01.corp.local", Kind: "Contains"},
			{Source: "USER:alice", Target: "GROUP:Domain Admins", Kind: "MemberOf"},
		},
		Meta: map[string]interface{}{"generator": "test"},
	}
}

func TestParseCupcakeGraphJSON(t *testing.T) {
	raw, _ := json.Marshal(sampleGraph())
	g, err := ParseCupcakeGraphBytes(raw, "graph.json")
	if err != nil {
		t.Fatal(err)
	}
	if g.Domain != "corp.local" || len(g.Nodes) != 4 || len(g.Edges) != 2 {
		t.Fatalf("got %+v", g)
	}
	prev := g.ToPreview()
	if prev.NodeCount != 4 || prev.EdgeCount != 2 {
		t.Fatalf("preview: %+v", prev)
	}
}

func TestParseCupcakeGraphZip(t *testing.T) {
	raw, _ := json.Marshal(sampleGraph())
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, err := zw.Create("graph.json")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(raw); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	g, err := ParseCupcakeGraphBytes(buf.Bytes(), "graph.zip")
	if err != nil {
		t.Fatal(err)
	}
	if len(g.Nodes) != 4 {
		t.Fatalf("nodes=%d", len(g.Nodes))
	}
}

func TestLoadCupcakeGraphFromArtifactFile(t *testing.T) {
	dir := t.TempDir()
	raw, _ := json.Marshal(sampleGraph())
	p := filepath.Join(dir, "graph.json")
	if err := os.WriteFile(p, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	g, err := LoadCupcakeGraphFromArtifact(p)
	if err != nil || g.Domain != "corp.local" {
		t.Fatalf("err=%v g=%+v", err, g)
	}
}

func TestIsGraphArtifact(t *testing.T) {
	if !IsGraphArtifact("ad_graph_collect", "", "") {
		t.Fatal("op")
	}
	if !IsGraphArtifact("x", "ad/a/1/graph.zip", "") {
		t.Fatal("path")
	}
	if IsGraphArtifact("kerberoast", "ad/a/1/result.hashcat.txt", "") {
		t.Fatal("should not be graph")
	}
}

func TestParseMisnamedSummaryZip(t *testing.T) {
	summary := []byte(`{"domain":"ceshi.c2","artifact":true,"format":"graph-v1-zip","node_count":2,"edge_count":1,"stdout_omits_graph":true}`)
	_, err := ParseCupcakeGraphBytes(summary, "graph.zip")
	if err == nil {
		t.Fatal("expected clear re-run error for summary-only")
	}
	if !strings.Contains(err.Error(), "re-run") && !strings.Contains(err.Error(), "missing") {
		t.Fatalf("err=%v", err)
	}
}

func TestParseSummaryWithInlineGraph(t *testing.T) {
	g := sampleGraph()
	gb, _ := json.Marshal(g)
	summary := map[string]interface{}{
		"domain":             "corp.local",
		"format":             "graph-v1-zip",
		"node_count":         4,
		"edge_count":         2,
		"stdout_omits_graph": false,
		"graph":              json.RawMessage(gb),
	}
	raw, _ := json.Marshal(summary)
	got, err := ParseCupcakeGraphBytes(raw, "graph.zip")
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Nodes) != 4 {
		t.Fatalf("nodes=%d", len(got.Nodes))
	}
}

func TestBuildCupcakeGraphZipFromJSON(t *testing.T) {
	raw, _ := json.Marshal(sampleGraph())
	z, err := BuildCupcakeGraphZipFromJSON(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !looksLikeZip(z) {
		t.Fatal("not zip")
	}
	g, err := ParseCupcakeGraphBytes(z, "graph.zip")
	if err != nil || g.Domain != "corp.local" {
		t.Fatalf("err=%v g=%+v", err, g)
	}
}

func TestBuildGraphFromDomainAndDCs(t *testing.T) {
	g := BuildGraphFromDomainAndDCs("ceshi.c2", []string{"WIN-JNDAJTM9K7E.ceshi.c2"})
	if len(g.Nodes) != 2 || len(g.Edges) != 1 {
		t.Fatalf("nodes=%d edges=%d", len(g.Nodes), len(g.Edges))
	}
	prev := g.ToPreview()
	if prev.NodeCount != 2 {
		t.Fatal(prev)
	}
}

func TestExtractFromLegacySummaryWithDCs(t *testing.T) {
	raw := []byte(`{"domain":"ceshi.c2","dcs":["dc1.ceshi.c2"],"format":"graph-v1-zip","node_count":2,"edge_count":1}`)
	g, err := ExtractCupcakeGraphFromJSONBytes(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(g.Nodes) != 2 {
		t.Fatalf("nodes=%d", len(g.Nodes))
	}
}

func TestExtractLegacySummaryDomainOnly(t *testing.T) {
	// Old task #29 shape
	raw := []byte(`{"artifact":true,"domain":"ceshi.c2","format":"graph-v1-zip","node_count":2,"edge_count":1,"stdout_omits_graph":true}`)
	g, err := ExtractCupcakeGraphFromJSONBytes(raw)
	if err != nil {
		t.Fatal(err)
	}
	if g.Domain != "ceshi.c2" || len(g.Nodes) < 1 {
		t.Fatalf("%+v", g)
	}
}
