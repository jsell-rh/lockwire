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

func testBar(out *bytes.Buffer, cols, rows uint16, text string) *statusBar {
	return newStatusBar(statusBarConfig{
		out:       out,
		cols:      cols,
		totalRows: rows,
		color:     colorCyberCyan,
		content:   func() string { return text },
	})
}

func TestStatusBarSteadyState(t *testing.T) {
	var buf bytes.Buffer
	sb := testBar(&buf, 80, 24, "lw | code: thunder-eagle-river-moon-stone-fire | 0 viewers")

	sb.Draw()
	output := buf.String()

	if !strings.Contains(output, "lw") {
		t.Error("status bar missing 'lw' prefix")
	}
	if !strings.Contains(output, "thunder-eagle-") {
		t.Error("status bar missing code fragment")
	}
	if !strings.Contains(output, "0 viewers") {
		t.Error("status bar should show 0 viewers")
	}
	if !strings.Contains(output, colorCyberCyan) {
		t.Error("status bar missing Cyber Cyan color sequence")
	}
	if !strings.Contains(output, "\0337") {
		t.Error("missing cursor save")
	}
	if !strings.Contains(output, "\0338") {
		t.Error("missing cursor restore")
	}
	if !strings.Contains(output, fmt.Sprintf("\033[%d;1H", 24)) {
		t.Error("status bar not positioned on bottom row")
	}
}

func TestStatusBarTransientMessage(t *testing.T) {
	var buf bytes.Buffer
	sb := testBar(&buf, 80, 24, "lw | steady state")

	sb.ShowEvent("viewer joined: a3k9x7 (cli)")
	output := buf.String()

	if !strings.Contains(output, "viewer joined: a3k9x7 (cli)") {
		t.Errorf("transient message not shown, got %q", output)
	}
	if strings.Contains(output, "steady state") {
		t.Error("transient message should replace steady state")
	}
}

func TestStatusBarTransientReverts(t *testing.T) {
	buf := &syncBuf{}
	sb := newStatusBar(statusBarConfig{
		out:       buf,
		cols:      80,
		totalRows: 24,
		color:     colorCyberCyan,
		content:   func() string { return "lw | steady state" },
	})
	sb.revertDelay = 50 * time.Millisecond

	sb.ShowEvent("viewer joined: a3k9x7 (cli)")
	time.Sleep(100 * time.Millisecond)

	buf.Reset()
	sb.Draw()
	if !strings.Contains(buf.String(), "steady state") {
		t.Errorf("expected steady state after revert, got %q", buf.String())
	}
}

func TestStatusBarResize(t *testing.T) {
	var buf bytes.Buffer
	sb := testBar(&buf, 80, 24, "lw | test")

	buf.Reset()
	sb.Resize(120, 40)

	output := buf.String()
	if !strings.Contains(output, "\033[1;39r") {
		t.Errorf("expected scroll region set to 1;39, got %q", output)
	}
	if !strings.Contains(output, fmt.Sprintf("\033[%d;1H", 40)) {
		t.Error("status bar not positioned on new bottom row")
	}
}

func TestStatusBarPadsToFullWidth(t *testing.T) {
	var buf bytes.Buffer
	sb := testBar(&buf, 40, 24, "lw | short")

	sb.Draw()
	output := buf.String()

	start := strings.Index(output, colorCyberCyan)
	end := strings.Index(output, colorReset)
	if start == -1 || end == -1 {
		t.Fatal("could not find color markers")
	}
	content := output[start+len(colorCyberCyan) : end]

	if len(content) != 40 {
		t.Errorf("status bar content length = %d, want 40 (terminal width)", len(content))
	}
}

func TestStatusBarSetScrollRegion(t *testing.T) {
	var buf bytes.Buffer
	sb := testBar(&buf, 80, 24, "lw | test")

	sb.SetScrollRegion()
	if !strings.Contains(buf.String(), "\033[1;23r") {
		t.Errorf("expected scroll region \\033[1;23r, got %q", buf.String())
	}
}

func TestStatusBarWarningAmberColor(t *testing.T) {
	var buf bytes.Buffer
	sb := newStatusBar(statusBarConfig{
		out:       &buf,
		cols:      80,
		totalRows: 24,
		color:     colorWarningAmber,
		content:   func() string { return "lw | watching test-code" },
	})

	sb.Draw()
	if !strings.Contains(buf.String(), colorWarningAmber) {
		t.Error("status bar missing Warning Amber color sequence")
	}
}
