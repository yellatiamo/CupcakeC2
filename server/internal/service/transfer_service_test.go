package services

import (
	"bytes"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"cupcake-server/pkg/paths"
)

func TestValidAgentUUID(t *testing.T) {
	if !ValidAgentUUID("550e8400-e29b-41d4-a716-446655440000") {
		t.Fatal("valid UUID rejected")
	}
	if ValidAgentUUID("") {
		t.Fatal("empty accepted")
	}
	if ValidAgentUUID("../etc/passwd") {
		t.Fatal("path traversal accepted")
	}
	if ValidAgentUUID("not-a-uuid") {
		t.Fatal("garbage accepted")
	}
	if ValidAgentUUID("550e8400e29b41d4a716446655440000") {
		t.Fatal("missing dashes accepted")
	}
}

func TestValidateAgentUploadGates(t *testing.T) {
	good := "550e8400-e29b-41d4-a716-446655440000"
	if st, _ := ValidateAgentUpload(good, 100); st != 0 {
		t.Fatalf("ok case status=%d", st)
	}
	if st, msg := ValidateAgentUpload(good, MaxAgentUploadBytes+1); st != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversize: status=%d msg=%s", st, msg)
	}
	// Exactly at max is allowed by size gate (disk checked separately).
	if st, _ := ValidateAgentUpload(good, MaxAgentUploadBytes); st != 0 {
		t.Fatalf("exact max should pass size gate, status=%d", st)
	}
	if st, msg := ValidateAgentUpload("", 10); st != http.StatusBadRequest || !strings.Contains(msg, "UUID") {
		t.Fatalf("empty uuid: %d %s", st, msg)
	}
	if st, msg := ValidateAgentUpload("bad", 10); st != http.StatusBadRequest || !strings.Contains(msg, "invalid") {
		t.Fatalf("bad uuid: %d %s", st, msg)
	}
	if MaxAgentUploadBytes != 256<<20 {
		t.Fatalf("MaxAgentUploadBytes = %d", MaxAgentUploadBytes)
	}
	// Size gate does not consult disk; oversized still 413 even if free is huge.
	if st, _ := ValidateAgentUpload(good, MaxAgentUploadBytes+1); st != http.StatusRequestEntityTooLarge {
		t.Fatalf("MaxAgentUploadBytes must still be enforced")
	}
}

func TestHandleAgentUploadRejectsBadUUID(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.POST("/upload", HandleAgentUpload)

	body := &bytes.Buffer{}
	w := multipart.NewWriter(body)
	part, err := w.CreateFormFile("file", "x.bin")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = part.Write([]byte("hi"))
	_ = w.WriteField("uuid", "not-valid")
	_ = w.Close()

	req := httptest.NewRequest(http.MethodPost, "/upload", body)
	req.Header.Set("Content-Type", w.FormDataContentType())
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("want 400 got %d body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "invalid agent UUID") {
		t.Fatalf("body: %s", rec.Body.String())
	}
}

func TestHandleAgentUploadHappyPath(t *testing.T) {
	gin.SetMode(gin.TestMode)
	tmp := t.TempDir()
	t.Setenv("CUPCAKE_DATA_DIR", tmp)
	paths.Init()
	InitTransfer()

	r := gin.New()
	r.POST("/upload", HandleAgentUpload)

	body := &bytes.Buffer{}
	mw := multipart.NewWriter(body)
	part, err := mw.CreateFormFile("file", "note.txt")
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte("agent-exfil-test")
	if _, err := part.Write(payload); err != nil {
		t.Fatal(err)
	}
	uuidStr := "550e8400-e29b-41d4-a716-446655440000"
	_ = mw.WriteField("uuid", uuidStr)
	_ = mw.Close()

	req := httptest.NewRequest(http.MethodPost, "/upload", body)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("want 200 got %d body=%s", rec.Code, rec.Body.String())
	}
	saved := filepath.Join(transferRoot(), uuidStr, "note.txt")
	got, err := os.ReadFile(saved)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("saved content mismatch")
	}
}
