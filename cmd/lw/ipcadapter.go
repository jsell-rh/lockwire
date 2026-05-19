package main

import (
	"context"
	"errors"

	"github.com/jsell-rh/lockwire/internal/ipc"
	"github.com/jsell-rh/lockwire/internal/session"
)

type ipcSessionAdapter struct {
	sess   *session.Session
	revoke func(ctx context.Context, viewerID string) error
}

func (a *ipcSessionAdapter) ListViewers() []ipc.ViewerInfo {
	sv := a.sess.ListViewers()
	result := make([]ipc.ViewerInfo, len(sv))
	for i, v := range sv {
		result[i] = ipc.ViewerInfo{
			ID:         v.ID,
			ClientType: v.ClientType,
			JoinTime:   v.JoinTime,
		}
	}
	return result
}

func (a *ipcSessionAdapter) RevokeViewer(id string) error {
	err := a.revoke(context.Background(), id)
	if err != nil && errors.Is(err, session.ErrViewerNotFound) {
		return ipc.ErrViewerNotFound
	}
	return err
}
