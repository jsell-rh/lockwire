package pty

import (
	"bytes"
	"strings"
	"sync"
	"testing"
	"time"
)

type recordingProbe struct {
	mu      sync.Mutex
	started []startEvent
	reads   []int
	resizes []sizeEvent
	exited  []error
}

type startEvent struct {
	pid        int
	cols, rows uint16
}

type sizeEvent struct {
	cols, rows uint16
}

func (p *recordingProbe) ShellStarted(pid int, cols, rows uint16) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.started = append(p.started, startEvent{pid, cols, rows})
}

func (p *recordingProbe) OutputRead(n int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.reads = append(p.reads, n)
}

func (p *recordingProbe) Resized(cols, rows uint16) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.resizes = append(p.resizes, sizeEvent{cols, rows})
}

func (p *recordingProbe) ShellExited(err error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.exited = append(p.exited, err)
}

func TestTerminalCapturesOutput(t *testing.T) {
	probe := &recordingProbe{}
	term, err := Start([]string{"/bin/sh", "-c", "echo hello-lockwire"}, Size{Cols: 80, Rows: 24}, probe)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer term.Close()

	var buf bytes.Buffer
	done := make(chan struct{})
	go func() {
		defer close(done)
		b := make([]byte, 4096)
		for {
			n, err := term.Read(b)
			if n > 0 {
				buf.Write(b[:n])
			}
			if err != nil {
				return
			}
		}
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for shell to exit")
	}

	// Wait for the process to fully exit so probe events are recorded.
	term.Wait()

	if !strings.Contains(buf.String(), "hello-lockwire") {
		t.Errorf("output = %q, want to contain %q", buf.String(), "hello-lockwire")
	}

	probe.mu.Lock()
	defer probe.mu.Unlock()

	if len(probe.started) != 1 {
		t.Fatalf("expected 1 start event, got %d", len(probe.started))
	}
	if probe.started[0].pid == 0 {
		t.Error("expected non-zero PID")
	}
	if probe.started[0].cols != 80 || probe.started[0].rows != 24 {
		t.Errorf("started with cols=%d rows=%d, want 80x24", probe.started[0].cols, probe.started[0].rows)
	}
	if len(probe.reads) == 0 {
		t.Error("expected at least one OutputRead event")
	}
	if len(probe.exited) != 1 {
		t.Errorf("expected 1 exit event, got %d", len(probe.exited))
	}
}

func TestTerminalWaitReturnsPID(t *testing.T) {
	term, err := Start([]string{"/bin/sh", "-c", "exit 0"}, Size{Cols: 80, Rows: 24}, nil)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer term.Close()

	pid := term.Pid()
	if pid == 0 {
		t.Error("expected non-zero PID")
	}

	// drain output
	go func() {
		b := make([]byte, 1024)
		for {
			_, err := term.Read(b)
			if err != nil {
				return
			}
		}
	}()

	if err := term.Wait(); err != nil {
		t.Errorf("Wait: %v", err)
	}
}

func TestTerminalSize(t *testing.T) {
	term, err := Start([]string{"/bin/sh", "-c", "sleep 10"}, Size{Cols: 120, Rows: 40}, nil)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer term.Close()

	size := term.Size()
	if size.Cols != 120 || size.Rows != 40 {
		t.Errorf("size = %dx%d, want 120x40", size.Cols, size.Rows)
	}
}
