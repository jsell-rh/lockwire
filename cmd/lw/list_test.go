package main

import (
	"bytes"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jsell-rh/lockwire/internal/ipc"
)

func TestListNoSession(t *testing.T) {
	removePIDFile()

	var stderr bytes.Buffer
	cmd := newRootCmd("test")
	cmd.SetErr(&stderr)
	cmd.SetArgs([]string{"list"})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error when no session is active")
	}
}

func TestListWithViewers(t *testing.T) {
	// Use a fake PID (99999) unlikely to collide.
	fakePID := 99999
	sockPath := ipc.SocketPath(fakePID)

	sess := &fakeIPCSession{
		viewers: []ipc.ViewerInfo{
			{ID: "a3k9x7", ClientType: "cli", JoinTime: time.Now().Add(-3 * time.Minute)},
			{ID: "m2p4n8", ClientType: "browser", JoinTime: time.Now().Add(-1 * time.Minute)},
		},
	}

	srv, err := ipc.NewServer(sockPath, sess, nil)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	defer srv.Close()
	go srv.Serve()

	os.WriteFile(pidFilePath(), []byte(strconv.Itoa(fakePID)), 0600)
	defer removePIDFile()

	var stdout bytes.Buffer
	cmd := newRootCmd("test")
	cmd.SetOut(&stdout)
	cmd.SetArgs([]string{"list"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}

	out := stdout.String()
	if !strings.Contains(out, "a3k9x7") {
		t.Errorf("output should contain viewer a3k9x7, got: %q", out)
	}
	if !strings.Contains(out, "m2p4n8") {
		t.Errorf("output should contain viewer m2p4n8, got: %q", out)
	}
	if !strings.Contains(out, "cli") {
		t.Errorf("output should contain 'cli', got: %q", out)
	}
	if !strings.Contains(out, "browser") {
		t.Errorf("output should contain 'browser', got: %q", out)
	}
	if !strings.Contains(out, "ago") {
		t.Errorf("output should contain 'ago', got: %q", out)
	}
}

func TestListNoViewers(t *testing.T) {
	fakePID := 99998
	sockPath := ipc.SocketPath(fakePID)

	sess := &fakeIPCSession{}
	srv, err := ipc.NewServer(sockPath, sess, nil)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	defer srv.Close()
	go srv.Serve()

	os.WriteFile(pidFilePath(), []byte(strconv.Itoa(fakePID)), 0600)
	defer removePIDFile()

	var stdout bytes.Buffer
	cmd := newRootCmd("test")
	cmd.SetOut(&stdout)
	cmd.SetArgs([]string{"list"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}

	if !strings.Contains(stdout.String(), "no viewers connected") {
		t.Errorf("expected 'no viewers connected', got: %q", stdout.String())
	}
}

func TestFormatDuration(t *testing.T) {
	tests := []struct {
		d    time.Duration
		want string
	}{
		{30 * time.Second, "30s ago"},
		{3 * time.Minute, "3m ago"},
		{90 * time.Minute, "1h ago"},
		{500 * time.Millisecond, "1s ago"},
	}

	for _, tt := range tests {
		got := formatDuration(tt.d)
		if got != tt.want {
			t.Errorf("formatDuration(%v) = %q, want %q", tt.d, got, tt.want)
		}
	}
}

// --- Shared test fake for IPC handler ---

type fakeIPCSession struct {
	viewers []ipc.ViewerInfo
}

func (f *fakeIPCSession) ListViewers() []ipc.ViewerInfo {
	return f.viewers
}

func (f *fakeIPCSession) RevokeViewer(id string) error {
	for i, v := range f.viewers {
		if v.ID == id {
			f.viewers = append(f.viewers[:i], f.viewers[i+1:]...)
			return nil
		}
	}
	return ipc.ErrViewerNotFound
}

func (f *fakeIPCSession) StopSession() error {
	return nil
}
