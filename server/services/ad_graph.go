package services

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"cupcake-server/pkg/model"
	"cupcake-server/pkg/store"
)

// Cupcake Graph v1: agent artifact + panel force-graph preview only.
// No BloodHound / OpenGraph export path.

// CupcakeNode is one node in cupcake-graph-v1.
type CupcakeNode struct {
	ID         string                 `json:"id"`
	Kind       string                 `json:"kind"`
	Name       string                 `json:"name"`
	Properties map[string]interface{} `json:"properties,omitempty"`
}

// CupcakeEdge is one edge in cupcake-graph-v1.
type CupcakeEdge struct {
	Source     string                 `json:"source"`
	Target     string                 `json:"target"`
	Kind       string                 `json:"kind"`
	Properties map[string]interface{} `json:"properties,omitempty"`
}

// CupcakeGraph is the documented agent graph payload.
type CupcakeGraph struct {
	Format string                 `json:"format"`
	Domain string                 `json:"domain"`
	Nodes  []CupcakeNode          `json:"nodes"`
	Edges  []CupcakeEdge          `json:"edges"`
	Meta   map[string]interface{} `json:"meta,omitempty"`
}

// LoadCupcakeGraphFromArtifact reads a graph artifact (graph.zip or bare .json).
func LoadCupcakeGraphFromArtifact(absPath string) (*CupcakeGraph, error) {
	data, err := os.ReadFile(absPath)
	if err != nil {
		return nil, fmt.Errorf("read artifact: %w", err)
	}
	return ParseCupcakeGraphBytes(data, filepath.Base(absPath))
}

// ParseCupcakeGraphBytes accepts ZIP (prefer graph.json), cupcake graph JSON,
// or agent summary JSON with nested "graph" (including misnamed graph.zip placeholders).
func ParseCupcakeGraphBytes(data []byte, filenameHint string) (*CupcakeGraph, error) {
	_ = filenameHint
	data = bytes.TrimSpace(data)
	if len(data) == 0 {
		return nil, fmt.Errorf("empty artifact")
	}

	// Real zip magic first — ignore filename (legacy wrote JSON under graph.zip).
	if looksLikeZip(data) {
		raw, err := extractZipFile(data, "graph.json")
		if err != nil {
			raw, err = extractFirstJSONFromZip(data)
			if err != nil {
				return nil, err
			}
		}
		return parseGraphOrSummaryJSON(raw)
	}

	return parseGraphOrSummaryJSON(data)
}

func parseGraphOrSummaryJSON(raw []byte) (*CupcakeGraph, error) {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || raw[0] != '{' {
		return nil, fmt.Errorf("artifact is not cupcake graph JSON (need re-run ad_graph_collect)")
	}
	var envelope struct {
		Format    string          `json:"format"`
		Domain    string          `json:"domain"`
		Nodes     json.RawMessage `json:"nodes"`
		Edges     json.RawMessage `json:"edges"`
		Graph     json.RawMessage `json:"graph"`
		NodeCount int             `json:"node_count"`
		EdgeCount int             `json:"edge_count"`
	}
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return nil, fmt.Errorf("graph json: %w", err)
	}
	if len(envelope.Graph) > 2 && string(envelope.Graph) != "null" {
		return unmarshalCupcakeGraph(envelope.Graph)
	}
	hasNodes := len(bytes.TrimSpace(envelope.Nodes)) > 0 && bytes.TrimSpace(envelope.Nodes)[0] == '['
	fmtLower := strings.ToLower(envelope.Format)
	if hasNodes {
		return unmarshalCupcakeGraph(raw)
	}
	if envelope.Domain != "" {
		return nil, fmt.Errorf("graph body missing (legacy summary-only artifact for %s: %d nodes) — re-run 图采集", envelope.Domain, envelope.NodeCount)
	}
	if strings.Contains(fmtLower, "graph") {
		return nil, fmt.Errorf("unrecognized graph artifact — re-run ad_graph_collect")
	}
	return nil, fmt.Errorf("unrecognized graph artifact — re-run ad_graph_collect")
}

// BuildCupcakeGraphZipFromJSON wraps a cupcake-graph-v1 JSON document as store-method ZIP.
func BuildCupcakeGraphZipFromJSON(graphJSON []byte) ([]byte, error) {
	if _, err := unmarshalCupcakeGraph(graphJSON); err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, err := zw.Create("graph.json")
	if err != nil {
		return nil, err
	}
	if _, err := w.Write(graphJSON); err != nil {
		_ = zw.Close()
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// looksLikeJSONSummary is true for text summary placeholders mis-stored as binary.
func looksLikeJSONSummary(data []byte) bool {
	s := bytes.TrimSpace(data)
	return len(s) > 0 && s[0] == '{'
}

func looksLikeZip(data []byte) bool {
	return len(data) >= 4 && data[0] == 0x50 && data[1] == 0x4b && (data[2] == 0x03 || data[2] == 0x05 || data[2] == 0x07)
}

func unmarshalCupcakeGraph(raw []byte) (*CupcakeGraph, error) {
	var g CupcakeGraph
	if err := json.Unmarshal(raw, &g); err != nil {
		return nil, fmt.Errorf("graph json: %w", err)
	}
	if g.Format == "" {
		g.Format = "cupcake-graph-v1"
	}
	if g.Nodes == nil {
		g.Nodes = []CupcakeNode{}
	}
	if g.Edges == nil {
		g.Edges = []CupcakeEdge{}
	}
	return &g, nil
}

func extractZipFile(data []byte, want string) ([]byte, error) {
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, fmt.Errorf("zip open: %w", err)
	}
	want = strings.ToLower(want)
	for _, f := range zr.File {
		base := strings.ToLower(filepath.Base(f.Name))
		if base == want || strings.EqualFold(f.Name, want) {
			return readZipEntry(f)
		}
	}
	return nil, fmt.Errorf("%s not found in zip", want)
}

func extractFirstJSONFromZip(data []byte) ([]byte, error) {
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, fmt.Errorf("zip open: %w", err)
	}
	for _, f := range zr.File {
		if strings.HasSuffix(strings.ToLower(f.Name), ".json") {
			return readZipEntry(f)
		}
	}
	return nil, fmt.Errorf("no json entry in zip")
}

func readZipEntry(f *zip.File) ([]byte, error) {
	rc, err := f.Open()
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	return io.ReadAll(rc)
}

// GraphPreviewDTO is returned by GET /api/ad/tasks/:id/graph for UI force layout.
type GraphPreviewDTO struct {
	Format    string                   `json:"format"`
	Domain    string                   `json:"domain"`
	NodeCount int                      `json:"node_count"`
	EdgeCount int                      `json:"edge_count"`
	Nodes     []map[string]interface{} `json:"nodes"`
	Edges     []map[string]interface{} `json:"edges"`
	Meta      map[string]interface{}   `json:"meta,omitempty"`
}

// ToPreview maps Cupcake graph into a UI-friendly DTO (stable ids for ECharts).
func (g *CupcakeGraph) ToPreview() *GraphPreviewDTO {
	dto := &GraphPreviewDTO{
		Format:    g.Format,
		Domain:    g.Domain,
		NodeCount: len(g.Nodes),
		EdgeCount: len(g.Edges),
		Nodes:     make([]map[string]interface{}, 0, len(g.Nodes)),
		Edges:     make([]map[string]interface{}, 0, len(g.Edges)),
		Meta:      g.Meta,
	}
	for _, n := range g.Nodes {
		id := strings.TrimSpace(n.ID)
		if id == "" {
			id = n.Kind + ":" + n.Name
		}
		kind := n.Kind
		if kind == "" {
			kind = "Unknown"
		}
		name := n.Name
		if name == "" {
			name = id
		}
		dto.Nodes = append(dto.Nodes, map[string]interface{}{
			"id":         id,
			"kind":       kind,
			"name":       name,
			"properties": n.Properties,
		})
	}
	for _, e := range g.Edges {
		dto.Edges = append(dto.Edges, map[string]interface{}{
			"source":     e.Source,
			"target":     e.Target,
			"kind":       e.Kind,
			"properties": e.Properties,
		})
	}
	return dto
}

// IsGraphArtifact reports whether task summary/op looks like graph collect.
func IsGraphArtifact(op, artifactPath, summaryJSON string) bool {
	op = strings.ToLower(strings.TrimSpace(op))
	if op == "ad_graph_collect" || op == "ad_acl_collect" {
		return true
	}
	p := strings.ToLower(artifactPath)
	if strings.Contains(p, "graph") && (strings.HasSuffix(p, ".zip") || strings.HasSuffix(p, ".json")) {
		return true
	}
	if strings.Contains(strings.ToLower(summaryJSON), "cupcake-graph") {
		return true
	}
	return false
}

// graphEnvelope is a tolerant parse of agent stdout / summary / artifact JSON.
type graphEnvelope struct {
	Format    string          `json:"format"`
	Domain    string          `json:"domain"`
	Nodes     json.RawMessage `json:"nodes"`
	Edges     json.RawMessage `json:"edges"`
	Graph     json.RawMessage `json:"graph"`
	DCs       []string        `json:"dcs"`
	NodeCount int             `json:"node_count"`
	EdgeCount int             `json:"edge_count"`
}

// ExtractCupcakeGraphFromJSONBytes extracts a displayable graph from any known payload shape.
func ExtractCupcakeGraphFromJSONBytes(raw []byte) (*CupcakeGraph, error) {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 {
		return nil, fmt.Errorf("empty")
	}
	if looksLikeZip(raw) {
		return ParseCupcakeGraphBytes(raw, "graph.zip")
	}
	// Nested or direct
	if g, err := ParseCupcakeGraphBytes(raw, "x.json"); err == nil && len(g.Nodes) > 0 {
		return g, nil
	}
	var env graphEnvelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, err
	}
	if len(env.Graph) > 2 && string(env.Graph) != "null" {
		if g, err := unmarshalCupcakeGraph(env.Graph); err == nil && len(g.Nodes) > 0 {
			return g, nil
		}
	}
	if env.Domain != "" {
		return BuildGraphFromDomainAndDCs(env.Domain, env.DCs), nil
	}
	return nil, fmt.Errorf("no graph data")
}

// BuildGraphFromDomainAndDCs builds a minimal Domain→DC Contains graph for UI preview.
func BuildGraphFromDomainAndDCs(domain string, dcs []string) *CupcakeGraph {
	domain = strings.TrimSpace(domain)
	nodes := []CupcakeNode{{
		ID:   "DOMAIN:" + domain,
		Kind: "Domain",
		Name: domain,
	}}
	edges := []CupcakeEdge{}
	seen := map[string]bool{}
	for _, dc := range dcs {
		dc = strings.TrimSpace(dc)
		if dc == "" || seen[dc] {
			continue
		}
		seen[dc] = true
		id := "COMPUTER:" + dc
		nodes = append(nodes, CupcakeNode{ID: id, Kind: "Computer", Name: dc})
		edges = append(edges, CupcakeEdge{
			Source: "DOMAIN:" + domain,
			Target: id,
			Kind:   "Contains",
		})
	}
	return &CupcakeGraph{
		Format: "cupcake-graph-v1",
		Domain: domain,
		Nodes:  nodes,
		Edges:  edges,
		Meta: map[string]interface{}{
			"generator": "cupcake-server",
			"source":    "reconstructed",
		},
	}
}

// LatestDiscoverDomainDCs returns domain + DCs from the newest completed ad_discover for agent.
func LatestDiscoverDomainDCs(agentUUID string) (domain string, dcs []string) {
	tasks, err := store.ListAdTasksByAgent(agentUUID)
	if err != nil {
		return "", nil
	}
	for _, t := range tasks {
		op := strings.ToLower(t.Op)
		if op != "ad_discover" || t.Status != "completed" || strings.TrimSpace(t.SummaryJSON) == "" {
			continue
		}
		var env graphEnvelope
		if json.Unmarshal([]byte(t.SummaryJSON), &env) != nil {
			continue
		}
		if env.Domain == "" && len(env.DCs) == 0 {
			continue
		}
		return env.Domain, env.DCs
	}
	return "", nil
}

// ResolveGraphForAdTask loads a previewable graph for an AD task.
// Order: real artifact → summary inline graph → summary domain+dcs → discover fallback.
// Also repairs legacy summary-only graph.zip on disk when reconstruction succeeds.
func ResolveGraphForAdTask(task *model.AdTask) (g *CupcakeGraph, source string, err error) {
	if task == nil {
		return nil, "", fmt.Errorf("nil task")
	}

	tryParse := func(label string, data []byte) bool {
		if len(bytes.TrimSpace(data)) == 0 {
			return false
		}
		got, e := ExtractCupcakeGraphFromJSONBytes(data)
		if e != nil || got == nil || len(got.Nodes) == 0 {
			return false
		}
		// Prefer graphs that have more than a lonely empty domain when possible
		g = got
		source = label
		return true
	}

	if task.ArtifactPath != "" {
		if abs, e := ResolveAdArtifactAbs(task.ArtifactPath); e == nil {
			if data, re := os.ReadFile(abs); re == nil {
				if tryParse("artifact", data) {
					// If artifact was summary-only but we only got domain node, try enrich below
					if len(g.Edges) > 0 || len(g.Nodes) > 1 {
						return g, source, nil
					}
				}
			}
		}
	}

	if tryParse("summary", []byte(task.SummaryJSON)) {
		if len(g.Edges) > 0 || len(g.Nodes) > 1 {
			_ = repairGraphArtifact(task, g)
			return g, source, nil
		}
	}

	// Enrich with discover DCs (fixes legacy graph.zip that only stored redacted summary)
	domain := ""
	var dcs []string
	if g != nil && g.Domain != "" {
		domain = g.Domain
	}
	var env graphEnvelope
	_ = json.Unmarshal([]byte(task.SummaryJSON), &env)
	if domain == "" {
		domain = env.Domain
	}
	dcs = append(dcs, env.DCs...)
	if discDomain, discDCs := LatestDiscoverDomainDCs(task.AgentUUID); len(discDCs) > 0 {
		if domain == "" {
			domain = discDomain
		}
		dcs = append(dcs, discDCs...)
	}
	if domain != "" {
		g = BuildGraphFromDomainAndDCs(domain, dcs)
		source = "reconstructed"
		_ = repairGraphArtifact(task, g)
		return g, source, nil
	}

	if g != nil && len(g.Nodes) > 0 {
		return g, source, nil
	}
	return nil, "", fmt.Errorf("graph body missing — re-run 图采集 (and ensure ad worker is latest)")
}

func repairGraphArtifact(task *model.AdTask, g *CupcakeGraph) error {
	if task == nil || g == nil || task.ID == 0 {
		return nil
	}
	raw, err := json.Marshal(g)
	if err != nil {
		return err
	}
	zipBytes, err := BuildCupcakeGraphZipFromJSON(raw)
	if err != nil {
		// store bare json
		rel, sha, n, werr := WriteAdArtifact(task.AgentUUID, fmt.Sprintf("%d", task.ID), "graph.json", raw)
		if werr != nil {
			return werr
		}
		return store.UpdateAdTaskResult(task.ReqID, task.SummaryJSON, rel, sha, n)
	}
	rel, sha, n, werr := WriteAdArtifact(task.AgentUUID, fmt.Sprintf("%d", task.ID), "graph.zip", zipBytes)
	if werr != nil {
		return werr
	}
	// Keep summary; refresh artifact pointer
	return store.UpdateAdTaskResult(task.ReqID, task.SummaryJSON, rel, sha, n)
}
