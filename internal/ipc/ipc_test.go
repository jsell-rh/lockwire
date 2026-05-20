package ipc

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// --- Fake session for IPC handler ---

type fakeSession struct {
	mu      sync.Mutex
	viewers []ViewerInfo
	revoked []string
	revokeErr error
}

func (f *fakeSession) ListViewers() []ViewerInfo {
	f.mu.Lock()
	defer f.mu.Unlock()
	cp := make([]ViewerInfo, len(f.viewers))
	copy(cp, f.viewers)
	return cp
}

func (f *fakeSession) RevokeViewer(id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.revokeErr != nil {
		return f.revokeErr
	}
	for i, v := range f.viewers {
		if v.ID == id {
			f.revoked = append(f.revoked, id)
			f.viewers = append(f.viewers[:i], f.viewers[i+1:]...)
			return nil
		}
	}
	return ErrViewerNotFound
}

func (f *fakeSession) StopSession() error {
	return nil
}

// --- Recording probe ---

type recordingProbe struct {
	mu             sync.Mutex
	listRequests   int
	revokeRequests []string
	errors         []error
}

func (p *recordingProbe) ListRequested()              { p.mu.Lock(); p.listRequests++; p.mu.Unlock() }
func (p *recordingProbe) RevokeRequested(viewerID string) {
	p.mu.Lock()
	p.revokeRequests = append(p.revokeRequests, viewerID)
	p.mu.Unlock()
}
func (p *recordingProbe) RequestFailed(err error) {
	p.mu.Lock()
	p.errors = append(p.errors, err)
	p.mu.Unlock()
}

// --- Tests ---

func TestServerListViewers(t *testing.T) {
	dir := t.TempDir()
	sockPath := filepath.Join(dir, "lw-test.sock")

	sess := &fakeSession{
		viewers: []ViewerInfo{
			{ID: "a3k9x7", ClientType: "cli", JoinTime: time.Now().Add(-3 * time.Minute)},
			{ID: "m2p4n8", ClientType: "browser", JoinTime: time.Now().Add(-1 * time.Minute)},
		},
	}
	probe := &recordingProbe{}

	srv, err := NewServer(sockPath, sess, probe)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	defer srv.Close()

	go srv.Serve()

	resp := sendRequest(t, sockPath, Request{Command: "list"})

	if resp.Error != "" {
		t.Fatalf("unexpected error: %s", resp.Error)
	}
	if len(resp.Viewers) != 2 {
		t.Fatalf("expected 2 viewers, got %d", len(resp.Viewers))
	}
	if resp.Viewers[0].ID != "a3k9x7" && resp.Viewers[1].ID != "a3k9x7" {
		t.Error("expected viewer a3k9x7 in list")
	}

	probe.mu.Lock()
	if probe.listRequests != 1 {
		t.Errorf("expected 1 list probe event, got %d", probe.listRequests)
	}
	probe.mu.Unlock()
}

func TestServerListNoViewers(t *testing.T) {
	dir := t.TempDir()
	sockPath := filepath.Join(dir, "lw-test.sock")

	sess := &fakeSession{}
	srv, err := NewServer(sockPath, sess, nil)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	defer srv.Close()

	go srv.Serve()

	resp := sendRequest(t, sockPath, Request{Command: "list"})
	if resp.Error != "" {
		t.Fatalf("unexpected error: %s", resp.Error)
	}
	if len(resp.Viewers) != 0 {
		t.Errorf("expected 0 viewers, got %d", len(resp.Viewers))
	}
}

func TestServerRevokeViewer(t *testing.T) {
	dir := t.TempDir()
	sockPath := filepath.Join(dir, "lw-test.sock")

	sess := &fakeSession{
		viewers: []ViewerInfo{
			{ID: "a3k9x7", ClientType: "cli", JoinTime: time.Now()},
			{ID: "m2p4n8", ClientType: "browser", JoinTime: time.Now()},
		},
	}
	probe := &recordingProbe{}

	srv, err := NewServer(sockPath, sess, probe)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	defer srv.Close()

	go srv.Serve()

	resp := sendRequest(t, sockPath, Request{Command: "revoke", ViewerID: "a3k9x7"})

	if resp.Error != "" {
		t.Fatalf("unexpected error: %s", resp.Error)
	}
	if !resp.OK {
		t.Error("expected OK=true")
	}

	sess.mu.Lock()
	if len(sess.revoked) != 1 || sess.revoked[0] != "a3k9x7" {
		t.Errorf("expected viewer a3k9x7 to be revoked, got %v", sess.revoked)
	}
	sess.mu.Unlock()

	probe.mu.Lock()
	if len(probe.revokeRequests) != 1 || probe.revokeRequests[0] != "a3k9x7" {
		t.Errorf("expected revoke probe for a3k9x7, got %v", probe.revokeRequests)
	}
	probe.mu.Unlock()
}

func TestServerRevokeUnknownViewer(t *testing.T) {
	dir := t.TempDir()
	sockPath := filepath.Join(dir, "lw-test.sock")

	sess := &fakeSession{
		viewers: []ViewerInfo{
			{ID: "a3k9x7", ClientType: "cli", JoinTime: time.Now()},
		},
	}

	srv, err := NewServer(sockPath, sess, nil)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	defer srv.Close()

	go srv.Serve()

	resp := sendRequest(t, sockPath, Request{Command: "revoke", ViewerID: "unknown"})

	if resp.Error != "viewer not found" {
		t.Errorf("expected 'viewer not found', got %q", resp.Error)
	}
	if resp.OK {
		t.Error("expected OK=false")
	}
}

func TestServerUnknownCommand(t *testing.T) {
	dir := t.TempDir()
	sockPath := filepath.Join(dir, "lw-test.sock")

	sess := &fakeSession{}
	srv, err := NewServer(sockPath, sess, nil)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	defer srv.Close()

	go srv.Serve()

	resp := sendRequest(t, sockPath, Request{Command: "bogus"})

	if resp.Error == "" {
		t.Error("expected an error for unknown command")
	}
}

func TestServerSocketPermissions(t *testing.T) {
	dir := t.TempDir()
	sockPath := filepath.Join(dir, "lw-test.sock")

	sess := &fakeSession{}
	srv, err := NewServer(sockPath, sess, nil)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	go srv.Serve()
	defer srv.Close()

	info, err := os.Stat(sockPath)
	if err != nil {
		t.Fatalf("stat socket: %v", err)
	}

	perm := info.Mode().Perm()
	if perm != 0600 {
		t.Errorf("socket permissions = %o, want 0600", perm)
	}
}

func TestServerCleanupSocket(t *testing.T) {
	dir := t.TempDir()
	sockPath := filepath.Join(dir, "lw-test.sock")

	sess := &fakeSession{}
	srv, err := NewServer(sockPath, sess, nil)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	go srv.Serve()

	if _, err := os.Stat(sockPath); err != nil {
		t.Fatalf("socket should exist: %v", err)
	}

	srv.Close()

	if _, err := os.Stat(sockPath); !os.IsNotExist(err) {
		t.Error("socket file should be removed after Close")
	}
}

func TestServerConcurrentRequests(t *testing.T) {
	dir := t.TempDir()
	sockPath := filepath.Join(dir, "lw-test.sock")

	sess := &fakeSession{
		viewers: []ViewerInfo{
			{ID: "a3k9x7", ClientType: "cli", JoinTime: time.Now()},
		},
	}

	srv, err := NewServer(sockPath, sess, nil)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	defer srv.Close()

	go srv.Serve()

	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp := sendRequest(t, sockPath, Request{Command: "list"})
			if resp.Error != "" {
				t.Errorf("concurrent list error: %s", resp.Error)
			}
		}()
	}
	wg.Wait()
}

func TestClientListConnectsToSocket(t *testing.T) {
	dir := t.TempDir()
	sockPath := filepath.Join(dir, "lw-test.sock")

	sess := &fakeSession{
		viewers: []ViewerInfo{
			{ID: "a3k9x7", ClientType: "cli", JoinTime: time.Now().Add(-2 * time.Minute)},
		},
	}

	srv, err := NewServer(sockPath, sess, nil)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	defer srv.Close()

	go srv.Serve()

	viewers, err := ClientList(sockPath)
	if err != nil {
		t.Fatalf("ClientList: %v", err)
	}
	if len(viewers) != 1 {
		t.Fatalf("expected 1 viewer, got %d", len(viewers))
	}
	if viewers[0].ID != "a3k9x7" {
		t.Errorf("viewer ID = %q, want a3k9x7", viewers[0].ID)
	}
}

func TestClientRevokeConnectsToSocket(t *testing.T) {
	dir := t.TempDir()
	sockPath := filepath.Join(dir, "lw-test.sock")

	sess := &fakeSession{
		viewers: []ViewerInfo{
			{ID: "a3k9x7", ClientType: "cli", JoinTime: time.Now()},
		},
	}

	srv, err := NewServer(sockPath, sess, nil)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	defer srv.Close()

	go srv.Serve()

	err = ClientRevoke(sockPath, "a3k9x7")
	if err != nil {
		t.Fatalf("ClientRevoke: %v", err)
	}

	sess.mu.Lock()
	if len(sess.revoked) != 1 {
		t.Errorf("expected 1 revocation, got %d", len(sess.revoked))
	}
	sess.mu.Unlock()
}

func TestClientRevokeUnknownReturnsError(t *testing.T) {
	dir := t.TempDir()
	sockPath := filepath.Join(dir, "lw-test.sock")

	sess := &fakeSession{}

	srv, err := NewServer(sockPath, sess, nil)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	defer srv.Close()

	go srv.Serve()

	err = ClientRevoke(sockPath, "nonexistent")
	if err == nil {
		t.Fatal("expected error for nonexistent viewer")
	}
	if err.Error() != "viewer not found" {
		t.Errorf("error = %q, want 'viewer not found'", err.Error())
	}
}

func TestSocketPath(t *testing.T) {
	path := SocketPath(12345)
	want := filepath.Join(os.TempDir(), "lw-12345.sock")
	if path != want {
		t.Errorf("SocketPath(12345) = %q, want %q", path, want)
	}
}

// --- Test helpers ---

func sendRequest(t *testing.T, sockPath string, req Request) Response {
	t.Helper()

	conn, err := net.Dial("unix", sockPath)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	if err := json.NewEncoder(conn).Encode(req); err != nil {
		t.Fatalf("encode request: %v", err)
	}

	var resp Response
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	return resp
}
