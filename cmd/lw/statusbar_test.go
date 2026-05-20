package main

import (
	"bytes"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

type syncBuf struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (sb *syncBuf) Write(p []byte) (int, error) {
	sb.mu.Lock()
	defer sb.mu.Unlock()
	return sb.buf.Write(p)
}

func (sb *syncBuf) Reset() {
	sb.mu.Lock()
	defer sb.mu.Unlock()
	sb.buf.Reset()
}

func (sb *syncBuf) String() string {
	sb.mu.Lock()
	defer sb.mu.Unlock()
	return sb.buf.String()
}

func TestStatusBarSteadyState(t *testing.T) {
	var buf bytes.Buffer
	sb := newStatusBar(&buf, 80, 24, "thunder-eagle-river-moon-stone-fire")

	sb.Draw()
	output := buf.String()

	if !strings.Contains(output, "lw") {
		t.Error("status bar missing 'lw' prefix")
	}
	if !strings.Contains(output, "thunder-eagle-") {
		t.Error("status bar missing code fragment")
	}
	if !strings.Contains(output, "0 viewers") {
		t.Error("status bar should show 0 viewers initially")
	}
	// Reverse video on
	if !strings.Contains(output, "\033[7m") {
		t.Error("status bar missing reverse video escape")
	}
	// Cursor save and restore (DEC)
	if !strings.Contains(output, "\0337") {
		t.Error("missing cursor save")
	}
	if !strings.Contains(output, "\0338") {
		t.Error("missing cursor restore")
	}
	// Positioned on row 24
	if !strings.Contains(output, fmt.Sprintf("\033[%d;1H", 24)) {
		t.Error("status bar not positioned on bottom row")
	}
}

func TestStatusBarViewerCount(t *testing.T) {
	var buf bytes.Buffer
	sb := newStatusBar(&buf, 80, 24, "test-code-one-two-three-four")

	sb.IncrementViewers()
	sb.Draw()
	if !strings.Contains(buf.String(), "1 viewer") {
		t.Errorf("expected '1 viewer', got %q", buf.String())
	}
	if strings.Contains(buf.String(), "1 viewers") {
		t.Error("should be singular 'viewer' not 'viewers'")
	}

	buf.Reset()
	sb.IncrementViewers()
	sb.Draw()
	if !strings.Contains(buf.String(), "2 viewers") {
		t.Errorf("expected '2 viewers', got %q", buf.String())
	}

	buf.Reset()
	sb.DecrementViewers()
	sb.Draw()
	if !strings.Contains(buf.String(), "1 viewer") {
		t.Errorf("expected '1 viewer' after decrement, got %q", buf.String())
	}
}

func TestStatusBarTransientMessage(t *testing.T) {
	var buf bytes.Buffer
	sb := newStatusBar(&buf, 80, 24, "test-code-one-two-three-four")

	sb.ShowEvent("viewer joined: a3k9x7 (cli)")
	output := buf.String()

	if !strings.Contains(output, "viewer joined: a3k9x7 (cli)") {
		t.Errorf("transient message not shown, got %q", output)
	}
	if strings.Contains(output, "0 viewers") {
		t.Error("transient message should replace steady state")
	}
}

func TestStatusBarTransientReverts(t *testing.T) {
	buf := &syncBuf{}
	sb := newStatusBar(buf, 80, 24, "test-code-one-two-three-four")
	sb.revertDelay = 50 * time.Millisecond

	sb.ShowEvent("viewer joined: a3k9x7 (cli)")
	time.Sleep(100 * time.Millisecond)

	buf.Reset()
	sb.Draw()
	if !strings.Contains(buf.String(), "0 viewers") {
		t.Errorf("expected steady state after revert, got %q", buf.String())
	}
}

func TestStatusBarResize(t *testing.T) {
	var buf bytes.Buffer
	sb := newStatusBar(&buf, 80, 24, "test-code-one-two-three-four")

	buf.Reset()
	sb.Resize(120, 40)

	output := buf.String()
	// Should set new scroll region
	if !strings.Contains(output, "\033[1;39r") {
		t.Errorf("expected scroll region set to 1;39, got %q", output)
	}
	// Should draw on new bottom row (40)
	if !strings.Contains(output, fmt.Sprintf("\033[%d;1H", 40)) {
		t.Error("status bar not positioned on new bottom row")
	}
}

func TestStatusBarPadsToFullWidth(t *testing.T) {
	var buf bytes.Buffer
	sb := newStatusBar(&buf, 40, 24, "ab-cd-ef-gh-ij-kl")

	sb.Draw()
	output := buf.String()

	// Find the content between reverse-video-on and reset
	start := strings.Index(output, "\033[7m")
	end := strings.Index(output, "\033[0m")
	if start == -1 || end == -1 {
		t.Fatal("could not find reverse video markers")
	}
	content := output[start+len("\033[7m") : end]

	if len(content) != 40 {
		t.Errorf("status bar content length = %d, want 40 (terminal width)", len(content))
	}
}

func TestStatusBarDecrementFloorAtZero(t *testing.T) {
	var buf bytes.Buffer
	sb := newStatusBar(&buf, 80, 24, "test-code-one-two-three-four")

	sb.DecrementViewers()
	sb.Draw()
	if !strings.Contains(buf.String(), "0 viewers") {
		t.Error("viewer count should not go below 0")
	}
}

func TestStatusBarSetScrollRegion(t *testing.T) {
	var buf bytes.Buffer
	sb := newStatusBar(&buf, 80, 24, "test-code-one-two-three-four")

	sb.SetScrollRegion()
	if !strings.Contains(buf.String(), "\033[1;23r") {
		t.Errorf("expected scroll region \\033[1;23r, got %q", buf.String())
	}
}
