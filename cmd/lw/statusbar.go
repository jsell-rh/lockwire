package main

import (
	"fmt"
	"io"
	"sync"
	"time"
)

type statusBar struct {
	mu          sync.Mutex
	out         io.Writer
	cols        uint16
	totalRows   uint16
	code        string
	viewerCount int
	transient   string
	revertTimer *time.Timer
	revertDelay time.Duration
}

func newStatusBar(out io.Writer, cols, totalRows uint16, code string) *statusBar {
	return &statusBar{
		out:         out,
		cols:        cols,
		totalRows:   totalRows,
		code:        code,
		revertDelay: 5 * time.Second,
	}
}

func (sb *statusBar) SetScrollRegion() {
	sb.mu.Lock()
	defer sb.mu.Unlock()
	fmt.Fprintf(sb.out, "\033[1;%dr", sb.totalRows-1)
}

func (sb *statusBar) Draw() {
	sb.mu.Lock()
	defer sb.mu.Unlock()
	sb.drawLocked()
}

func (sb *statusBar) drawLocked() {
	content := sb.renderContent()
	padded := padOrTruncate(content, int(sb.cols))
	fmt.Fprintf(sb.out, "\0337\033[%d;1H\033[7m%s\033[0m\0338", sb.totalRows, padded)
}

func (sb *statusBar) renderContent() string {
	if sb.transient != "" {
		return sb.transient
	}
	return sb.steadyState()
}

func (sb *statusBar) steadyState() string {
	noun := "viewers"
	if sb.viewerCount == 1 {
		noun = "viewer"
	}
	return fmt.Sprintf("lw | code: %s | %d %s", sb.code, sb.viewerCount, noun)
}

func (sb *statusBar) ShowEvent(msg string) {
	sb.mu.Lock()
	sb.transient = "lw | " + msg
	if sb.revertTimer != nil {
		sb.revertTimer.Stop()
	}
	delay := sb.revertDelay
	sb.revertTimer = time.AfterFunc(delay, func() {
		sb.mu.Lock()
		sb.transient = ""
		sb.drawLocked()
		sb.mu.Unlock()
	})
	sb.drawLocked()
	sb.mu.Unlock()
}

func (sb *statusBar) IncrementViewers() {
	sb.mu.Lock()
	sb.viewerCount++
	sb.mu.Unlock()
}

func (sb *statusBar) DecrementViewers() {
	sb.mu.Lock()
	if sb.viewerCount > 0 {
		sb.viewerCount--
	}
	sb.mu.Unlock()
}

func (sb *statusBar) Resize(cols, totalRows uint16) {
	sb.mu.Lock()
	sb.cols = cols
	sb.totalRows = totalRows
	fmt.Fprintf(sb.out, "\033[1;%dr", totalRows-1)
	sb.drawLocked()
	sb.mu.Unlock()
}

func (sb *statusBar) Close() {
	sb.mu.Lock()
	if sb.revertTimer != nil {
		sb.revertTimer.Stop()
	}
	sb.mu.Unlock()
}

func padOrTruncate(s string, width int) string {
	if len(s) >= width {
		return s[:width]
	}
	buf := make([]byte, width)
	copy(buf, s)
	for i := len(s); i < width; i++ {
		buf[i] = ' '
	}
	return string(buf)
}
