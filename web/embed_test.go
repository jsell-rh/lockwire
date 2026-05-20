package web

import (
	"io/fs"
	"strings"
	"testing"
)

func TestAssetsContainIndexHTML(t *testing.T) {
	data, err := fs.ReadFile(Assets, "dist/index.html")
	if err != nil {
		t.Fatalf("reading dist/index.html from embedded assets: %v", err)
	}
	if len(data) == 0 {
		t.Fatal("dist/index.html is empty")
	}
}

func TestIndexHTMLStructure(t *testing.T) {
	data, err := fs.ReadFile(Assets, "dist/index.html")
	if err != nil {
		t.Fatalf("reading dist/index.html: %v", err)
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
		{"fragment extraction", "location.hash"},
		{"connecting state", `connecting`},
	}

	for _, c := range checks {
		if !strings.Contains(html, c.content) {
			t.Errorf("dist/index.html missing %s (expected %q)", c.name, c.content)
		}
	}
}

func TestIndexHTMLNoCodeInServerRequest(t *testing.T) {
	data, err := fs.ReadFile(Assets, "dist/index.html")
	if err != nil {
		t.Fatalf("reading dist/index.html: %v", err)
	}
	html := string(data)

	if strings.Contains(html, "window.location.search") {
		t.Error("dist/index.html must not read query string (code must stay in fragment only)")
	}
}
