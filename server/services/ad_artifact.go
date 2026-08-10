package services

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"cupcake-server/pkg/paths"
)

// AdSummaryV1 is the agent→server artifact/summary contract (design §7.2).
type AdSummaryV1 struct {
	Domain        string          `json:"domain"`
	Kind          string          `json:"kind"`
	HashCount     int             `json:"hash_count"`
	Artifact      bool            `json:"artifact"`
	ArtifactPath  string          `json:"artifact_path"`
	ArtifactBytes int64           `json:"artifact_bytes"`
	Format        string          `json:"format"`
	Hashes        json.RawMessage `json:"hashes"` // must NOT be persisted to CommandLog when large
	NodeCount     int             `json:"node_count"`
	EdgeCount     int             `json:"edge_count"`
	StdoutOmits   bool            `json:"stdout_omits_graph"`
	// Graph is the full cupcake-graph-v1 document when agent inlines it (preview source of truth).
	Graph json.RawMessage `json:"graph,omitempty"`
}

// DefaultAdStdoutInlineMax is CUPCAKE_AD_STDOUT_INLINE_MAX default (256 KiB).
const DefaultAdStdoutInlineMax = 256 * 1024

// ParseAdSummary parses agent stdout as summary JSON (tolerant of plain "pong").
func ParseAdSummary(stdout string) (*AdSummaryV1, error) {
	stdout = strings.TrimSpace(stdout)
	if stdout == "" || stdout == "pong" || stdout == "ok" {
		return &AdSummaryV1{}, nil
	}
	if !strings.HasPrefix(stdout, "{") {
		return &AdSummaryV1{}, nil
	}
	var s AdSummaryV1
	if err := json.Unmarshal([]byte(stdout), &s); err != nil {
		return nil, fmt.Errorf("summary json: %w", err)
	}
	return &s, nil
}

// NeedsArtifactStorage reports whether the summary or size requires file storage.
func NeedsArtifactStorage(summary *AdSummaryV1, stdoutLen int, inlineMax int) bool {
	if inlineMax <= 0 {
		inlineMax = DefaultAdStdoutInlineMax
	}
	if summary != nil && summary.Artifact {
		return true
	}
	if summary != nil && summary.ArtifactPath != "" {
		return true
	}
	if stdoutLen > inlineMax {
		return true
	}
	return false
}

// SanitizeSummaryForLog strips full hash dumps from summary JSON for CommandLog.
func SanitizeSummaryForLog(stdout string) string {
	s, err := ParseAdSummary(stdout)
	if err != nil || s == nil {
		if len(stdout) > DefaultAdStdoutInlineMax {
			return fmt.Sprintf(`{"truncated":true,"original_bytes":%d}`, len(stdout))
		}
		return stdout
	}
	hasGraph := len(s.Graph) > 0 && string(s.Graph) != "null"
	if len(s.Hashes) > 0 || (s.HashCount > 0 && s.Artifact) || s.StdoutOmits || hasGraph {
		// Rebuild without hashes / full graph (CommandLog stays small)
		out := map[string]interface{}{
			"domain":       s.Domain,
			"kind":         s.Kind,
			"hash_count":   s.HashCount,
			"artifact":     s.Artifact || s.ArtifactPath != "",
			"format":       s.Format,
			"node_count":   s.NodeCount,
			"edge_count":   s.EdgeCount,
			"log_redacted": true,
		}
		if s.ArtifactPath != "" {
			out["artifact_path"] = s.ArtifactPath
		}
		if hasGraph {
			out["stdout_omits_graph"] = false
			out["graph_inline"] = true
		}
		b, _ := json.Marshal(out)
		return string(b)
	}
	if len(stdout) > DefaultAdStdoutInlineMax {
		return fmt.Sprintf(`{"truncated":true,"original_bytes":%d,"log_redacted":true}`, len(stdout))
	}
	return stdout
}

// AdStorageDir returns storage/ad/{agent}/{task}/ absolute path.
func AdStorageDir(agentUUID, taskID string) string {
	base := paths.Root()
	if base == "" {
		base = "storage"
	}
	return filepath.Join(base, "ad", sanitizePathPart(agentUUID), sanitizePathPart(taskID))
}

func sanitizePathPart(s string) string {
	s = strings.TrimSpace(s)
	s = strings.ReplaceAll(s, "..", "_")
	s = strings.ReplaceAll(s, string(filepath.Separator), "_")
	s = strings.ReplaceAll(s, "/", "_")
	s = strings.ReplaceAll(s, "\\", "_")
	if s == "" {
		return "_empty"
	}
	return s
}

// WriteAdArtifact writes bytes under storage/ad and returns path + sha256 + size.
func WriteAdArtifact(agentUUID, taskID, filename string, data []byte) (relPath, sha string, n int64, err error) {
	dir := AdStorageDir(agentUUID, taskID)
	if err = os.MkdirAll(dir, 0o700); err != nil {
		return "", "", 0, err
	}
	filename = sanitizePathPart(filepath.Base(filename))
	if filename == "" || filename == "_empty" {
		filename = "result.bin"
	}
	full := filepath.Join(dir, filename)
	if err = os.WriteFile(full, data, 0o600); err != nil {
		return "", "", 0, err
	}
	sum := sha256.Sum256(data)
	sha = hex.EncodeToString(sum[:])
	// relative from data dir for portability
	relPath = filepath.Join("ad", sanitizePathPart(agentUUID), sanitizePathPart(taskID), filename)
	return relPath, sha, int64(len(data)), nil
}

// WriteAdMetaJSON writes meta.json next to the artifact.
func WriteAdMetaJSON(agentUUID, taskID string, meta map[string]interface{}) error {
	dir := AdStorageDir(agentUUID, taskID)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "meta.json"), b, 0o600)
}

// ResolveAdArtifactAbs joins data dir with relative artifact path (traversal-safe).
func ResolveAdArtifactAbs(rel string) (string, error) {
	rel = filepath.Clean(rel)
	if strings.Contains(rel, "..") {
		return "", fmt.Errorf("access_denied: path traversal")
	}
	if !strings.HasPrefix(rel, "ad"+string(filepath.Separator)) && !strings.HasPrefix(rel, "ad/") {
		// allow only under ad/
		if !strings.HasPrefix(filepath.ToSlash(rel), "ad/") {
			return "", fmt.Errorf("access_denied: outside storage/ad")
		}
	}
	base := paths.Root()
	if base == "" {
		base = "storage"
	}
	full := filepath.Join(base, rel)
	// ensure still under base/ad
	adRoot := filepath.Join(base, "ad")
	absFull, _ := filepath.Abs(full)
	absRoot, _ := filepath.Abs(adRoot)
	if !strings.HasPrefix(strings.ToLower(absFull), strings.ToLower(absRoot)) {
		return "", fmt.Errorf("access_denied: outside storage/ad")
	}
	return full, nil
}
