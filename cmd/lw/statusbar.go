package main

import (
	"fmt"
	"io"
	"sync"
	"time"
)

const (
	colorCyberCyan   = "\033[30;48;2;0;240;255m"
	colorWarningAmber = "\033[30;48;2;255;176;0m"
	colorReset       = "\033[0m"
)

type statusBar struct {
	mu          sync.Mutex
	out         io.Writer
	cols        uint16
	totalRows   uint16
	colorSeq    string
	content     func() string
	transient   string
	revertTimer *time.Timer
	revertDelay time.Duration
}

type statusBarConfig struct {
	out       io.Writer
	cols      uint16
	totalRows uint16
	color     string
	content   func() string
}

func newStatusBar(cfg statusBarConfig) *statusBar {
	return &statusBar{
		out:         cfg.out,
		cols:        cfg.cols,
		totalRows:   cfg.totalRows,
		colorSeq:    cfg.color,
		content:     cfg.content,
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
	var text string
	if sb.transient != "" {
		text = sb.transient
	} else {
		text = sb.content()
	}
	padded := padOrTruncate(text, int(sb.cols))
	fmt.Fprintf(sb.out, "\0337\033[%d;1H%s%s%s\0338", sb.totalRows, sb.colorSeq, padded, colorReset)
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

type barRedrawWriter struct {
	w   io.Writer
	bar *statusBar
}

func (bw *barRedrawWriter) Write(p []byte) (int, error) {
	n, err := bw.w.Write(p)
	bw.bar.Draw()
	return n, err
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
