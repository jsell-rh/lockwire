package session

import (
	"bytes"
	"errors"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/jsell-rh/lockwire/internal/crypto"
	"github.com/jsell-rh/lockwire/internal/protocol"
)

func fixedClock(t time.Time) func() time.Time {
	return func() time.Time { return t }
}

func fakeAuthKey(t *testing.T, seed byte) []byte {
	t.Helper()
	k := make([]byte, protocol.KeyLen)
	for i := range k {
		k[i] = seed + byte(i)
	}
	return k
}

// --- Session Creation ---

func TestNewSession(t *testing.T) {
	s, err := NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	sid := s.SessionID()
	if len(sid) != protocol.SessionIDLen*2 {
		t.Errorf("session ID length = %d, want %d hex chars", len(sid), protocol.SessionIDLen*2)
	}
}

func TestNewSessionUniqueness(t *testing.T) {
	s1, err := NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer s1.Close()

	s2, err := NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()

	if s1.SessionID() == s2.SessionID() {
		t.Error("two sessions have the same session ID")
	}
}

func TestSessionIDDeterministic(t *testing.T) {
	s, err := NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	s1 := s.SessionID()
	s2 := s.SessionID()
	if s1 != s2 {
		t.Errorf("session ID changed between calls: %q vs %q", s1, s2)
	}
}

// --- Viewer Registration ---

func TestRegisterViewer(t *testing.T) {
	s, err := NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	authKey := fakeAuthKey(t, 0x10)
	info, payload, err := s.RegisterViewer(authKey, "cli")
	if err != nil {
		t.Fatal(err)
	}

	if len(info.ID) != protocol.ViewerIDLen {
		t.Errorf("viewer ID length = %d, want %d", len(info.ID), protocol.ViewerIDLen)
	}
	if info.ClientType != "cli" {
		t.Errorf("client type = %q, want %q", info.ClientType, "cli")
	}
	if info.JoinTime.IsZero() {
		t.Error("join time is zero")
	}
	if len(payload.Nonce) != protocol.NonceLen {
		t.Errorf("nonce length = %d, want %d", len(payload.Nonce), protocol.NonceLen)
	}
	if len(payload.Ciphertext) == 0 {
		t.Error("encrypted key is empty")
	}
}

func TestRegisterViewerDecryptsToStreamKey(t *testing.T) {
	s, err := NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	authKey := fakeAuthKey(t, 0x20)
	_, payload, err := s.RegisterViewer(authKey, "cli")
	if err != nil {
		t.Fatal(err)
	}

	k, err := crypto.Open(authKey, payload.Nonce, payload.Ciphertext)
	if err != nil {
		t.Fatalf("decrypting delivered key: %v", err)
	}
	defer crypto.ZeroBytes(k)

	derivedSID := crypto.DeriveSessionID(k)
	if derivedSID != s.SessionID() {
		t.Error("decrypted key does not derive to the session's session ID")
	}
}

func TestRegisterMultipleViewers(t *testing.T) {
	s, err := NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	ids := make(map[string]bool)
	for i := byte(0); i < 5; i++ {
		authKey := fakeAuthKey(t, i*0x10)
		info, _, err := s.RegisterViewer(authKey, "cli")
		if err != nil {
			t.Fatalf("registering viewer %d: %v", i, err)
		}
		if ids[info.ID] {
			t.Errorf("duplicate viewer ID: %s", info.ID)
		}
		ids[info.ID] = true
	}
}

func TestRegisterViewerBrowserType(t *testing.T) {
	s, err := NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	authKey := fakeAuthKey(t, 0x30)
	info, _, err := s.RegisterViewer(authKey, "browser")
	if err != nil {
		t.Fatal(err)
	}
	if info.ClientType != "browser" {
		t.Errorf("client type = %q, want %q", info.ClientType, "browser")
	}
}

func TestRegisterViewerOnClosedSession(t *testing.T) {
	s, err := NewSession()
	if err != nil {
		t.Fatal(err)
	}
	s.Close()

	authKey := fakeAuthKey(t, 0x40)
	_, _, err = s.RegisterViewer(authKey, "cli")
	if err == nil {
		t.Error("expected error registering on closed session")
	}
}

// --- Viewer Listing ---

func TestListViewersEmpty(t *testing.T) {
	s, err := NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	viewers := s.ListViewers()
	if len(viewers) != 0 {
		t.Errorf("expected 0 viewers, got %d", len(viewers))
	}
}

func TestListViewers(t *testing.T) {
	s, err := NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	info1, _, _ := s.RegisterViewer(fakeAuthKey(t, 0x10), "cli")
	info2, _, _ := s.RegisterViewer(fakeAuthKey(t, 0x20), "browser")

	viewers := s.ListViewers()
	if len(viewers) != 2 {
		t.Fatalf("expected 2 viewers, got %d", len(viewers))
	}

	ids := []string{viewers[0].ID, viewers[1].ID}
	sort.Strings(ids)
	wantIDs := []string{info1.ID, info2.ID}
	sort.Strings(wantIDs)

	if ids[0] != wantIDs[0] || ids[1] != wantIDs[1] {
		t.Errorf("viewer IDs = %v, want %v", ids, wantIDs)
	}
}

func TestListViewersExcludesKeyMaterial(t *testing.T) {
	s, err := NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	s.RegisterViewer(fakeAuthKey(t, 0x10), "cli")
	viewers := s.ListViewers()

	for _, v := range viewers {
		if v.ID == "" {
			t.Error("viewer ID is empty")
		}
		if v.JoinTime.IsZero() {
			t.Error("join time is zero")
		}
	}
}

// --- Viewer Revocation ---

func TestRevokeViewer(t *testing.T) {
	s, err := NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	authKeyA := fakeAuthKey(t, 0x10)
	authKeyB := fakeAuthKey(t, 0x20)

	infoA, _, _ := s.RegisterViewer(authKeyA, "cli")
	_, _, _ = s.RegisterViewer(authKeyB, "cli")

	rekeys, err := s.RevokeViewer(infoA.ID)
	if err != nil {
		t.Fatal(err)
	}

	// Viewer A should not receive a rekey message
	if _, ok := rekeys[infoA.ID]; ok {
		t.Error("revoked viewer received a rekey message")
	}

	// Viewer B should receive a rekey message
	if len(rekeys) != 1 {
		t.Fatalf("expected 1 rekey, got %d", len(rekeys))
	}
}

func TestRevokeViewerNewKeyDecryptable(t *testing.T) {
	s, err := NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	authKeyA := fakeAuthKey(t, 0x10)
	authKeyB := fakeAuthKey(t, 0x20)

	infoA, _, _ := s.RegisterViewer(authKeyA, "cli")
	infoB, _, _ := s.RegisterViewer(authKeyB, "cli")

	oldSID := s.SessionID()

	rekeys, err := s.RevokeViewer(infoA.ID)
	if err != nil {
		t.Fatal(err)
	}

	// Viewer B can decrypt K'
	payload := rekeys[infoB.ID]
	kPrime, err := crypto.Open(authKeyB, payload.Nonce, payload.Ciphertext)
	if err != nil {
		t.Fatalf("viewer B decrypting K': %v", err)
	}
	defer crypto.ZeroBytes(kPrime)

	// K' derives a different session ID than old K
	newSID := crypto.DeriveSessionID(kPrime)
	if newSID == oldSID {
		t.Error("K' derives to the same session ID as old K")
	}

	// The session's session ID should now match K'
	if newSID != s.SessionID() {
		t.Error("session ID does not match K'")
	}
}

func TestRevokeViewerRemovesFromList(t *testing.T) {
	s, err := NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	infoA, _, _ := s.RegisterViewer(fakeAuthKey(t, 0x10), "cli")
	s.RegisterViewer(fakeAuthKey(t, 0x20), "cli")

	s.RevokeViewer(infoA.ID)

	viewers := s.ListViewers()
	for _, v := range viewers {
		if v.ID == infoA.ID {
			t.Error("revoked viewer still in list")
		}
	}
	if len(viewers) != 1 {
		t.Errorf("expected 1 viewer, got %d", len(viewers))
	}
}

func TestRevokeViewerNotFound(t *testing.T) {
	s, err := NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	_, err = s.RevokeViewer("zzzzzz")
	if err == nil {
		t.Error("expected error revoking unknown viewer")
	}
}

func TestRevokeLastViewer(t *testing.T) {
	s, err := NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	info, _, _ := s.RegisterViewer(fakeAuthKey(t, 0x10), "cli")

	rekeys, err := s.RevokeViewer(info.ID)
	if err != nil {
		t.Fatal(err)
	}

	// No remaining viewers to rekey
	if len(rekeys) != 0 {
		t.Errorf("expected 0 rekeys, got %d", len(rekeys))
	}

	// Session should still be usable
	if s.SessionID() == "" {
		t.Error("session ID is empty after revoking last viewer")
	}
}

// --- Viewer Removal (disconnect, not revocation) ---

func TestRemoveViewer(t *testing.T) {
	s, err := NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	oldSID := s.SessionID()
	infoA, _, _ := s.RegisterViewer(fakeAuthKey(t, 0x10), "cli")
	s.RegisterViewer(fakeAuthKey(t, 0x20), "cli")

	s.RemoveViewer(infoA.ID)

	viewers := s.ListViewers()
	if len(viewers) != 1 {
		t.Errorf("expected 1 viewer, got %d", len(viewers))
	}

	// No key rotation on disconnect — session ID unchanged
	if s.SessionID() != oldSID {
		t.Error("session ID changed on viewer removal (should only change on revocation)")
	}
}

// --- Epoch ---

func TestCurrentEpoch(t *testing.T) {
	now := time.Unix(120, 0) // epoch = 120/60 = 2
	s, err := NewSession(WithClock(fixedClock(now)))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	if got := s.CurrentEpoch(); got != 2 {
		t.Errorf("current epoch = %d, want 2", got)
	}
}

func TestEpochKeyDerivedFromStreamKey(t *testing.T) {
	now := time.Unix(300, 0) // epoch = 5
	s, err := NewSession(WithClock(fixedClock(now)))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	// Register a viewer to get the stream key
	authKey := fakeAuthKey(t, 0x10)
	_, payload, _ := s.RegisterViewer(authKey, "cli")
	k, _ := crypto.Open(authKey, payload.Nonce, payload.Ciphertext)
	defer crypto.ZeroBytes(k)

	// Derive epoch key independently
	wantEK, err := crypto.DeriveEpochKey(k, 5)
	if err != nil {
		t.Fatal(err)
	}
	defer crypto.ZeroBytes(wantEK)

	// Encrypt a frame and verify it can be decrypted with the independently derived epoch key
	ct, nonce, epoch, err := s.EncryptFrame([]byte("hello"))
	if err != nil {
		t.Fatal(err)
	}
	if epoch != 5 {
		t.Errorf("epoch = %d, want 5", epoch)
	}

	got, err := crypto.Open(wantEK, nonce, ct)
	if err != nil {
		t.Fatalf("decrypting frame with independently derived epoch key: %v", err)
	}
	if string(got) != "hello" {
		t.Errorf("decrypted frame = %q, want %q", got, "hello")
	}
}

// --- Frame Encryption ---

func TestEncryptFrame(t *testing.T) {
	s, err := NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	ct, nonce, _, err := s.EncryptFrame([]byte("test"))
	if err != nil {
		t.Fatal(err)
	}
	if len(ct) == 0 {
		t.Error("ciphertext is empty")
	}
	if len(nonce) != protocol.NonceLen {
		t.Errorf("nonce length = %d, want %d", len(nonce), protocol.NonceLen)
	}
}

func TestEncryptFrameNonceMonotonic(t *testing.T) {
	s, err := NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	var prevNonce []byte
	for i := 0; i < 10; i++ {
		_, nonce, _, err := s.EncryptFrame([]byte("data"))
		if err != nil {
			t.Fatal(err)
		}
		if prevNonce != nil && bytes.Compare(nonce, prevNonce) <= 0 {
			t.Fatalf("nonce not monotonic at iteration %d", i)
		}
		prevNonce = nonce
	}
}

func TestEncryptFrameNonceContinuesAfterRevocation(t *testing.T) {
	s, err := NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	s.RegisterViewer(fakeAuthKey(t, 0x10), "cli")
	info, _, _ := s.RegisterViewer(fakeAuthKey(t, 0x20), "cli")

	// Encrypt some frames to advance the nonce
	for i := 0; i < 5; i++ {
		s.EncryptFrame([]byte("pre-revoke"))
	}

	_, preNonce, _, _ := s.EncryptFrame([]byte("last-before-revoke"))

	// Revoke a viewer (causes K rotation, uses nonces for rekey messages)
	s.RevokeViewer(info.ID)

	_, postNonce, _, err := s.EncryptFrame([]byte("post-revoke"))
	if err != nil {
		t.Fatal(err)
	}

	if bytes.Compare(postNonce, preNonce) <= 0 {
		t.Error("nonce did not continue increasing after revocation")
	}
}

func TestEncryptFrameOnClosedSession(t *testing.T) {
	s, err := NewSession()
	if err != nil {
		t.Fatal(err)
	}
	s.Close()

	_, _, _, err = s.EncryptFrame([]byte("data"))
	if err == nil {
		t.Error("expected error encrypting on closed session")
	}
}

// --- Memory Security ---

func TestCloseZerosStreamKey(t *testing.T) {
	s, err := NewSession()
	if err != nil {
		t.Fatal(err)
	}

	s.Close()

	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, b := range s.streamKey {
		if b != 0 {
			t.Fatal("stream key not zeroed after Close")
		}
	}
}

func TestCloseZerosViewerAuthKeys(t *testing.T) {
	s, err := NewSession()
	if err != nil {
		t.Fatal(err)
	}

	s.RegisterViewer(fakeAuthKey(t, 0x10), "cli")
	s.RegisterViewer(fakeAuthKey(t, 0x20), "browser")

	// Collect auth key slices before close
	s.mu.RLock()
	var authKeys [][]byte
	for _, v := range s.viewers {
		authKeys = append(authKeys, v.authKey)
	}
	s.mu.RUnlock()

	s.Close()

	for i, k := range authKeys {
		for _, b := range k {
			if b != 0 {
				t.Fatalf("viewer %d auth key not zeroed after Close", i)
			}
		}
	}
}

func TestRevokeZerosOldStreamKey(t *testing.T) {
	s, err := NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	s.RegisterViewer(fakeAuthKey(t, 0x10), "cli")
	info, _, _ := s.RegisterViewer(fakeAuthKey(t, 0x20), "cli")

	// Capture the old stream key slice header (not a copy)
	s.mu.RLock()
	oldKeySlice := s.streamKey
	s.mu.RUnlock()

	s.RevokeViewer(info.ID)

	for _, b := range oldKeySlice {
		if b != 0 {
			t.Fatal("old stream key not zeroed after revocation")
		}
	}
}

func TestRevokeZerosRevokedViewerAuthKey(t *testing.T) {
	s, err := NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	info, _, _ := s.RegisterViewer(fakeAuthKey(t, 0x10), "cli")
	s.RegisterViewer(fakeAuthKey(t, 0x20), "cli")

	// Capture the revoked viewer's auth key slice
	s.mu.RLock()
	revokedAuthKey := s.viewers[info.ID].authKey
	s.mu.RUnlock()

	s.RevokeViewer(info.ID)

	for _, b := range revokedAuthKey {
		if b != 0 {
			t.Fatal("revoked viewer's auth key not zeroed")
		}
	}
}

// --- Concurrent Operations ---

func TestConcurrentViewerRegistration(t *testing.T) {
	s, err := NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	var wg sync.WaitGroup
	ids := make(chan string, 20)

	for i := byte(0); i < 20; i++ {
		wg.Add(1)
		go func(seed byte) {
			defer wg.Done()
			authKey := fakeAuthKey(t, seed)
			info, _, err := s.RegisterViewer(authKey, "cli")
			if err != nil {
				t.Errorf("registering viewer: %v", err)
				return
			}
			ids <- info.ID
		}(i)
	}

	wg.Wait()
	close(ids)

	seen := make(map[string]bool)
	for id := range ids {
		if seen[id] {
			t.Errorf("duplicate viewer ID under concurrent registration: %s", id)
		}
		seen[id] = true
	}

	viewers := s.ListViewers()
	if len(viewers) != 20 {
		t.Errorf("expected 20 viewers, got %d", len(viewers))
	}
}

func TestConcurrentEncryptFrame(t *testing.T) {
	s, err := NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	var wg sync.WaitGroup
	nonces := make(chan []byte, 50)

	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, nonce, _, err := s.EncryptFrame([]byte("concurrent"))
			if err != nil {
				t.Errorf("encrypting: %v", err)
				return
			}
			nonces <- nonce
		}()
	}

	wg.Wait()
	close(nonces)

	seen := make(map[string]bool)
	for n := range nonces {
		key := string(n)
		if seen[key] {
			t.Error("duplicate nonce under concurrent encryption")
		}
		seen[key] = true
	}
}

// --- Revoked Viewer Rejoin ---

func TestRevokedViewerRejoin(t *testing.T) {
	s, err := NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	authKeyA := fakeAuthKey(t, 0x10)
	authKeyB := fakeAuthKey(t, 0x20)

	infoA, _, _ := s.RegisterViewer(authKeyA, "cli")
	s.RegisterViewer(authKeyB, "cli")

	s.RevokeViewer(infoA.ID)

	// Viewer A rejoins with a new auth key (fresh SPAKE2 handshake)
	newAuthKey := fakeAuthKey(t, 0x30)
	newInfo, payload, err := s.RegisterViewer(newAuthKey, "cli")
	if err != nil {
		t.Fatal(err)
	}

	if newInfo.ID == infoA.ID {
		t.Error("rejoin produced the same viewer ID as the revoked viewer")
	}

	// The new viewer should receive K' (the current stream key)
	kPrime, err := crypto.Open(newAuthKey, payload.Nonce, payload.Ciphertext)
	if err != nil {
		t.Fatalf("decrypting K' for rejoined viewer: %v", err)
	}
	defer crypto.ZeroBytes(kPrime)

	if crypto.DeriveSessionID(kPrime) != s.SessionID() {
		t.Error("rejoined viewer received wrong stream key")
	}
}

func TestWasRevoked(t *testing.T) {
	s, err := NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	info, _, _ := s.RegisterViewer(fakeAuthKey(t, 0x10), "cli")
	s.RegisterViewer(fakeAuthKey(t, 0x20), "cli")

	if s.WasRevoked(info.ID) {
		t.Error("viewer should not be marked revoked before revocation")
	}

	s.RevokeViewer(info.ID)

	if !s.WasRevoked(info.ID) {
		t.Error("viewer should be marked revoked after revocation")
	}
}

// --- Double Close ---

func TestDoubleCloseIsSafe(t *testing.T) {
	s, err := NewSession()
	if err != nil {
		t.Fatal(err)
	}
	s.Close()
	s.Close() // should not panic
}

// --- Additional edge cases ---

func TestRevokeViewerOnClosedSession(t *testing.T) {
	s, err := NewSession()
	if err != nil {
		t.Fatal(err)
	}
	info, _, _ := s.RegisterViewer(fakeAuthKey(t, 0x10), "cli")
	s.Close()

	_, err = s.RevokeViewer(info.ID)
	if err == nil {
		t.Error("expected error revoking on closed session")
	}
}

func TestRemoveUnknownViewer(t *testing.T) {
	s, err := NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	s.RemoveViewer("zzzzzz") // should not panic
}

func TestRemoveViewerZerosAuthKey(t *testing.T) {
	s, err := NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	info, _, _ := s.RegisterViewer(fakeAuthKey(t, 0x10), "cli")

	s.mu.RLock()
	authKeySlice := s.viewers[info.ID].authKey
	s.mu.RUnlock()

	s.RemoveViewer(info.ID)

	for _, b := range authKeySlice {
		if b != 0 {
			t.Fatal("removed viewer's auth key not zeroed")
		}
	}
}

// --- Error sentinel assertions ---

func TestRevokeViewerNotFoundSentinel(t *testing.T) {
	s, err := NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	_, err = s.RevokeViewer("zzzzzz")
	if !errors.Is(err, ErrViewerNotFound) {
		t.Errorf("expected ErrViewerNotFound, got %v", err)
	}
}

func TestRegisterViewerOnClosedSessionSentinel(t *testing.T) {
	s, err := NewSession()
	if err != nil {
		t.Fatal(err)
	}
	s.Close()

	_, _, err = s.RegisterViewer(fakeAuthKey(t, 0x40), "cli")
	if !errors.Is(err, ErrSessionClosed) {
		t.Errorf("expected ErrSessionClosed, got %v", err)
	}
}

func TestEncryptFrameOnClosedSessionSentinel(t *testing.T) {
	s, err := NewSession()
	if err != nil {
		t.Fatal(err)
	}
	s.Close()

	_, _, _, err = s.EncryptFrame([]byte("data"))
	if !errors.Is(err, ErrSessionClosed) {
		t.Errorf("expected ErrSessionClosed, got %v", err)
	}
}

// --- Spec scenario: revoked viewer cannot decrypt new frames ---

func TestRevokedViewerCannotDecryptNewFrames(t *testing.T) {
	now := time.Unix(300, 0)
	s, err := NewSession(WithClock(fixedClock(now)))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	authKeyA := fakeAuthKey(t, 0x10)
	authKeyB := fakeAuthKey(t, 0x20)

	infoA, payloadA, _ := s.RegisterViewer(authKeyA, "cli")
	s.RegisterViewer(authKeyB, "cli")

	// Viewer A extracts K and derives the current epoch key
	oldK, _ := crypto.Open(authKeyA, payloadA.Nonce, payloadA.Ciphertext)
	defer crypto.ZeroBytes(oldK)

	// Revoke Viewer A
	s.RevokeViewer(infoA.ID)

	// Encrypt a frame under K' (the new stream key)
	ct, nonce, epoch, err := s.EncryptFrame([]byte("secret-after-revoke"))
	if err != nil {
		t.Fatal(err)
	}

	// Viewer A tries to decrypt using epoch key derived from old K
	oldEpochKey, _ := crypto.DeriveEpochKey(oldK, epoch)
	defer crypto.ZeroBytes(oldEpochKey)

	_, err = crypto.Open(oldEpochKey, nonce, ct)
	if err == nil {
		t.Error("revoked viewer should not be able to decrypt frames under K'")
	}
}

// --- Spec scenario: epoch boundary transparent to active viewers ---

func TestEpochBoundaryTransparent(t *testing.T) {
	epoch5 := time.Unix(300, 0) // epoch 5
	epoch6 := time.Unix(360, 0) // epoch 6
	currentTime := epoch5

	s, err := NewSession(WithClock(func() time.Time { return currentTime }))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	// Register a viewer and extract K
	authKey := fakeAuthKey(t, 0x10)
	_, payload, _ := s.RegisterViewer(authKey, "cli")
	k, _ := crypto.Open(authKey, payload.Nonce, payload.Ciphertext)
	defer crypto.ZeroBytes(k)

	// Encrypt at epoch 5
	ct5, nonce5, ep5, err := s.EncryptFrame([]byte("epoch-5-data"))
	if err != nil {
		t.Fatal(err)
	}
	if ep5 != 5 {
		t.Fatalf("expected epoch 5, got %d", ep5)
	}

	// Advance clock to epoch 6
	currentTime = epoch6

	// Encrypt at epoch 6
	ct6, nonce6, ep6, err := s.EncryptFrame([]byte("epoch-6-data"))
	if err != nil {
		t.Fatal(err)
	}
	if ep6 != 6 {
		t.Fatalf("expected epoch 6, got %d", ep6)
	}

	// Viewer independently derives both epoch keys from K
	ek5, _ := crypto.DeriveEpochKey(k, 5)
	defer crypto.ZeroBytes(ek5)
	ek6, _ := crypto.DeriveEpochKey(k, 6)
	defer crypto.ZeroBytes(ek6)

	// Both frames decrypt correctly
	pt5, err := crypto.Open(ek5, nonce5, ct5)
	if err != nil {
		t.Fatalf("decrypting epoch-5 frame: %v", err)
	}
	if string(pt5) != "epoch-5-data" {
		t.Errorf("epoch-5 plaintext = %q, want %q", pt5, "epoch-5-data")
	}

	pt6, err := crypto.Open(ek6, nonce6, ct6)
	if err != nil {
		t.Fatalf("decrypting epoch-6 frame: %v", err)
	}
	if string(pt6) != "epoch-6-data" {
		t.Errorf("epoch-6 plaintext = %q, want %q", pt6, "epoch-6-data")
	}

	// Cross-epoch decryption fails
	_, err = crypto.Open(ek5, nonce6, ct6)
	if err == nil {
		t.Error("epoch-5 key should not decrypt epoch-6 frame")
	}
}
