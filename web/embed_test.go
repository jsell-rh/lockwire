package web

import (
	"io/fs"
	"strings"
	"testing"
)

func TestAssetsContainIndexHTML(t *testing.T) {
	data, err := fs.ReadFile(Assets, "index.html")
	if err != nil {
		t.Fatalf("reading index.html from embedded assets: %v", err)
	}
	if len(data) == 0 {
		t.Fatal("index.html is empty")
	}
}

func TestIndexHTMLStructure(t *testing.T) {
	data, err := fs.ReadFile(Assets, "index.html")
	if err != nil {
		t.Fatalf("reading index.html: %v", err)
	}
	html := string(data)

	checks := []struct {
		name    string
		content string
	}{
		{"code input", `id="code"`},
		{"watch button", `id="watch"`},
		{"Watch label", ">Watch<"},
		{"status display", `id="status"`},
		{"fragment extraction", "window.location.hash"},
		{"connecting state", `connecting`},
	}

	for _, c := range checks {
		if !strings.Contains(html, c.content) {
			t.Errorf("index.html missing %s (expected %q)", c.name, c.content)
		}
	}
}

func TestIndexHTMLNoCodeInServerRequest(t *testing.T) {
	data, err := fs.ReadFile(Assets, "index.html")
	if err != nil {
		t.Fatalf("reading index.html: %v", err)
	}
	html := string(data)

	if strings.Contains(html, "window.location.search") {
		t.Error("index.html must not read query string (code must stay in fragment only)")
	}
	if strings.Contains(html, "window.location.pathname") && strings.Contains(html, "code") {
		t.Error("index.html must not extract code from pathname (code must stay in fragment only)")
	}
}
