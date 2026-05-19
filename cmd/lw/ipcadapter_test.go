package main

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jsell-rh/lockwire/internal/ipc"
	"github.com/jsell-rh/lockwire/internal/session"
)

func TestAdapterListConvertsViewerInfo(t *testing.T) {
	now := time.Now()
	sess, err := session.NewSession([]byte("test-code"), session.WithClock(func() time.Time { return now }))
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	defer sess.Close()

	authKey := make([]byte, 32)
	authKey[0] = 0x01
	info, _, err := sess.RegisterViewer(authKey, "cli")
	if err != nil {
		t.Fatalf("RegisterViewer: %v", err)
	}

	adapter := &ipcSessionAdapter{
		sess:   sess,
		revoke: func(_ context.Context, _ string) error { return nil },
	}

	viewers := adapter.ListViewers()
	if len(viewers) != 1 {
		t.Fatalf("expected 1 viewer, got %d", len(viewers))
	}
	if viewers[0].ID != info.ID {
		t.Errorf("viewer ID = %q, want %q", viewers[0].ID, info.ID)
	}
	if viewers[0].ClientType != "cli" {
		t.Errorf("client type = %q, want cli", viewers[0].ClientType)
	}
}

func TestAdapterRevokeTranslatesError(t *testing.T) {
	adapter := &ipcSessionAdapter{
		sess: nil,
		revoke: func(_ context.Context, id string) error {
			return session.ErrViewerNotFound
		},
	}

	err := adapter.RevokeViewer("unknown")
	if !errors.Is(err, ipc.ErrViewerNotFound) {
		t.Errorf("expected ipc.ErrViewerNotFound, got: %v", err)
	}
}

func TestAdapterRevokeSuccess(t *testing.T) {
	var revokedID string
	adapter := &ipcSessionAdapter{
		sess: nil,
		revoke: func(_ context.Context, id string) error {
			revokedID = id
			return nil
		},
	}

	err := adapter.RevokeViewer("a3k9x7")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if revokedID != "a3k9x7" {
		t.Errorf("revoked ID = %q, want a3k9x7", revokedID)
	}
}
