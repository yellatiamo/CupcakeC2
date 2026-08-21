package services

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestProfileMatchesRequest(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/mail/u/0/?sync=1", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 Chrome/126.0.0.0 Safari/537.36")
	req.Header.Set("X-Gmail-Travel", "true")
	if !profileMatchesRequest(req, "gmail") {
		t.Fatal("gmail should match")
	}
	if !profileMatchesRequest(req, "") {
		t.Fatal("empty profile always ok")
	}
	bad := httptest.NewRequest(http.MethodGet, "/ws", nil)
	bad.Header.Set("User-Agent", "curl/8.0")
	if profileMatchesRequest(bad, "gmail") {
		t.Fatal("curl should not match gmail")
	}
	owa := httptest.NewRequest(http.MethodGet, "/owa/sessiondata.ashx", nil)
	owa.Header.Set("X-OWA-Version", "16.0.17714.2")
	if !profileMatchesRequest(owa, "outlook") {
		t.Fatal("outlook should match")
	}
}
