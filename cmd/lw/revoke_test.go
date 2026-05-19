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

func TestRevokeNoSession(t *testing.T) {
	removePIDFile()

	cmd := newRootCmd("test")
	cmd.SetArgs([]string{"revoke", "a3k9x7"})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error when no session is active")
	}
}

func TestRevokeSuccess(t *testing.T) {
	fakePID := 99997
	sockPath := ipc.SocketPath(fakePID)

	sess := &fakeIPCSession{
		viewers: []ipc.ViewerInfo{
			{ID: "a3k9x7", ClientType: "cli", JoinTime: time.Now()},
			{ID: "m2p4n8", ClientType: "browser", JoinTime: time.Now()},
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
	cmd.SetArgs([]string{"revoke", "a3k9x7"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}

	out := stdout.String()
	if !strings.Contains(out, "revoked a3k9x7") {
		t.Errorf("expected 'revoked a3k9x7', got: %q", out)
	}
}

func TestRevokeUnknownViewer(t *testing.T) {
	fakePID := 99996
	sockPath := ipc.SocketPath(fakePID)

	sess := &fakeIPCSession{
		viewers: []ipc.ViewerInfo{
			{ID: "a3k9x7", ClientType: "cli", JoinTime: time.Now()},
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

	cmd := newRootCmd("test")
	cmd.SetArgs([]string{"revoke", "unknown-id"})

	err = cmd.Execute()
	if err == nil {
		t.Fatal("expected error for unknown viewer")
	}
	if !strings.Contains(err.Error(), "viewer not found") {
		t.Errorf("expected 'viewer not found', got: %q", err.Error())
	}
}

func TestRevokeMissingArg(t *testing.T) {
	cmd := newRootCmd("test")
	cmd.SetArgs([]string{"revoke"})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error when no viewer ID provided")
	}
}
