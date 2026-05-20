package web

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jsell-rh/lockwire/internal/relay"
)

func TestRelayServesEmbeddedAssets(t *testing.T) {
	srv := relay.NewServer(relay.WithWebAssets(Assets))
	ts := httptest.NewServer(srv)
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/join")
	if err != nil {
		t.Fatalf("GET /join: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	html := string(body)

	if !strings.Contains(html, "Lockwire") {
		t.Error("served page missing Lockwire title")
	}
	if !strings.Contains(html, `id="code"`) {
		t.Error("served page missing code input")
	}
	if !strings.Contains(html, "Watch") {
		t.Error("served page missing Watch button")
	}
}
