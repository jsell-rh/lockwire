package viewer

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/jsell-rh/lockwire/internal/crypto"
	"github.com/jsell-rh/lockwire/internal/protocol"
	"github.com/jsell-rh/lockwire/internal/session"
)

var testCode = []byte("thunder-eagle-river-moon-stone-fire")

// --- Thread-safe output buffer ---

type safeBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *safeBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *safeBuffer) Len() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Len()
}

func (b *safeBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func (b *safeBuffer) Reset() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.buf.Reset()
}

// --- Fake relay ---

type fakeRelay struct {
	mu       sync.Mutex
	incoming chan []byte
	sent     [][]byte
	closed   bool
}

func newFakeRelay() *fakeRelay {
	return &fakeRelay{
		incoming: make(chan []byte, 64),
	}
}

func (f *fakeRelay) Send(_ context.Context, msg []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return errors.New("relay closed")
	}
	cp := make([]byte, len(msg))
	copy(cp, msg)
	f.sent = append(f.sent, cp)
	return nil
}

func (f *fakeRelay) Recv(ctx context.Context) ([]byte, error) {
	select {
	case msg, ok := <-f.incoming:
		if !ok {
			return nil, errors.New("relay closed")
		}
		return msg, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (f *fakeRelay) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.closed {
		f.closed = true
		close(f.incoming)
	}
	return nil
}

func (f *fakeRelay) getSent() [][]byte {
	f.mu.Lock()
	defer f.mu.Unlock()
	cp := make([][]byte, len(f.sent))
	copy(cp, f.sent)
	return cp
}

// --- Recording probe ---

type recordingProbe struct {
	mu             sync.Mutex
	connecting     bool
	completed      string
	frames         []int
	ended          string
	hsFailed       error
	heartbeats     int
	keyRotations   int
	accessRevoked  bool
	resizes        []sizeEvent
}

type sizeEvent struct {
	cols, rows uint16
}

func (p *recordingProbe) Connecting()                    { p.mu.Lock(); p.connecting = true; p.mu.Unlock() }
func (p *recordingProbe) HandshakeCompleted(id string)   { p.mu.Lock(); p.completed = id; p.mu.Unlock() }
func (p *recordingProbe) FrameDecrypted(_ uint64, n int) { p.mu.Lock(); p.frames = append(p.frames, n); p.mu.Unlock() }
func (p *recordingProbe) StreamKeyRotated()              { p.mu.Lock(); p.keyRotations++; p.mu.Unlock() }
func (p *recordingProbe) AccessRevoked()                 { p.mu.Lock(); p.accessRevoked = true; p.mu.Unlock() }
func (p *recordingProbe) SessionEnded(reason string)     { p.mu.Lock(); p.ended = reason; p.mu.Unlock() }
func (p *recordingProbe) HandshakeFailed(err error)      { p.mu.Lock(); p.hsFailed = err; p.mu.Unlock() }
func (p *recordingProbe) HeartbeatSent()                 { p.mu.Lock(); p.heartbeats++; p.mu.Unlock() }
func (p *recordingProbe) TerminalResized(cols, rows uint16) {
	p.mu.Lock()
	p.resizes = append(p.resizes, sizeEvent{cols, rows})
	p.mu.Unlock()
}

// --- Sharer-side handshake helper ---

type handshakeResult struct {
	viewerID string
	authKey  []byte
}

// simulateSharerHandshake runs the sharer side of the SPAKE2 handshake
// against the viewer's messages on the fake relay. It registers the viewer
// on the session and delivers the stream key. Returns the viewer's auth key
// so callers can build K' delivery messages for revocation tests.
func simulateSharerHandshake(t *testing.T, relay *fakeRelay, sess *session.Session, code []byte) handshakeResult {
	t.Helper()

	// Send join ack
	relay.incoming <- []byte{protocol.MsgTypeControl, protocol.CtrlJoinAck, 'v', '0', '0', '0', '0', '0'}

	// Wait for viewer's SPAKE2 init
	waitForSent(t, relay, 1)

	// Create sharer-side SPAKE2
	sharerSpake, err := crypto.NewSPAKE2Sharer(code)
	if err != nil {
		t.Fatalf("creating sharer SPAKE2: %v", err)
	}
	defer sharerSpake.Destroy()

	msgA, err := sharerSpake.Start()
	if err != nil {
		t.Fatalf("SPAKE2 start: %v", err)
	}

	// Send msg_a to viewer (unicast — no type prefix, as relay strips it)
	relay.incoming <- msgA

	// Wait for viewer's msg_b
	waitForSent(t, relay, 2)
	sent := relay.getSent()
	msgBWithPrefix := sent[1]
	if msgBWithPrefix[0] != protocol.MsgTypeSPAKE2 {
		t.Fatalf("expected SPAKE2 type byte, got 0x%02x", msgBWithPrefix[0])
	}
	msgB := msgBWithPrefix[1:]

	confirmA, err := sharerSpake.Finish(msgB)
	if err != nil {
		t.Fatalf("SPAKE2 finish: %v", err)
	}

	// Send confirm_a to viewer
	relay.incoming <- confirmA

	// Wait for viewer's confirm_b
	waitForSent(t, relay, 3)
	sent = relay.getSent()
	confirmBWithPrefix := sent[2]
	confirmB := confirmBWithPrefix[1:]

	if err := sharerSpake.Verify(confirmB); err != nil {
		t.Fatalf("SPAKE2 verify: %v", err)
	}

	spakeSecret, err := sharerSpake.SessionKey()
	if err != nil {
		t.Fatalf("session key: %v", err)
	}
	defer crypto.ZeroBytes(spakeSecret)

	authKey, err := crypto.DeriveAuthKey(spakeSecret)
	if err != nil {
		t.Fatalf("deriving auth key: %v", err)
	}

	info, encPayload, err := sess.RegisterViewer(authKey, protocol.ClientTypeCLI)
	if err != nil {
		t.Fatalf("registering viewer: %v", err)
	}

	// Build key delivery: viewerID(6) + nonce(12) + ciphertext
	delivery := make([]byte, protocol.ViewerIDLen+protocol.NonceLen+len(encPayload.Ciphertext))
	copy(delivery[:protocol.ViewerIDLen], info.ID)
	copy(delivery[protocol.ViewerIDLen:protocol.ViewerIDLen+protocol.NonceLen], encPayload.Nonce)
	copy(delivery[protocol.ViewerIDLen+protocol.NonceLen:], encPayload.Ciphertext)

	relay.incoming <- delivery

	// Return a copy of the auth key — caller owns it and must zero it.
	authKeyCopy := make([]byte, len(authKey))
	copy(authKeyCopy, authKey)

	return handshakeResult{viewerID: info.ID, authKey: authKeyCopy}
}

func waitForSent(t *testing.T, relay *fakeRelay, count int) {
	t.Helper()
	deadline := time.After(5 * time.Second)
	for {
		if len(relay.getSent()) >= count {
			return
		}
		select {
		case <-deadline:
			t.Fatalf("timed out waiting for %d sent messages (have %d)", count, len(relay.getSent()))
		default:
			time.Sleep(5 * time.Millisecond)
		}
	}
}

// --- Tests ---

func TestHandshakeAndStreamDecryption(t *testing.T) {
	relay := newFakeRelay()
	output := &safeBuffer{}
	probe := &recordingProbe{}

	sess, err := session.NewSession(testCode)
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()

	v := New(relay, testCode, output, probe)

	errCh := make(chan error, 1)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		errCh <- v.Run(ctx)
	}()

	simulateSharerHandshake(t, relay, sess, testCode)
	waitForProbe(t, probe)

	if !probe.connecting {
		t.Error("Connecting probe not called")
	}
	if len(probe.completed) != protocol.ViewerIDLen {
		t.Errorf("viewer ID length = %d, want %d", len(probe.completed), protocol.ViewerIDLen)
	}

	ct, nonce, epoch, err := sess.EncryptFrame([]byte("hello viewer"))
	if err != nil {
		t.Fatal(err)
	}
	relay.incoming <- buildStreamFrame(ct, nonce, epoch)

	waitForOutput(t, output)

	if got := output.String(); got != "hello viewer" {
		t.Errorf("output = %q, want %q", got, "hello viewer")
	}

	cancel()
	select {
	case err := <-errCh:
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("viewer did not stop")
	}
}

func TestViewerSendsClientTypeInInit(t *testing.T) {
	relay := newFakeRelay()
	output := &safeBuffer{}
	probe := &recordingProbe{}

	sess, err := session.NewSession(testCode)
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()

	v := New(relay, testCode, output, probe, WithClientType(protocol.ClientByteBrowser))

	errCh := make(chan error, 1)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		errCh <- v.Run(ctx)
	}()

	// Send join ack
	relay.incoming <- []byte{protocol.MsgTypeControl, protocol.CtrlJoinAck, 'v', '0', '0', '0', '0', '0'}

	// Wait for the viewer's SPAKE2 init message
	waitForSent(t, relay, 1)
	sent := relay.getSent()
	initMsg := sent[0]

	if initMsg[0] != protocol.MsgTypeSPAKE2 {
		t.Fatalf("expected SPAKE2 type byte, got 0x%02x", initMsg[0])
	}
	if len(initMsg) < 2 {
		t.Fatal("expected client type byte in SPAKE2 init, got only type byte")
	}
	if initMsg[1] != protocol.ClientByteBrowser {
		t.Errorf("client type byte = 0x%02x, want 0x%02x (browser)", initMsg[1], protocol.ClientByteBrowser)
	}

	cancel()
	<-errCh
}

func TestViewerDefaultsToCliClientType(t *testing.T) {
	relay := newFakeRelay()
	v := New(relay, testCode, &safeBuffer{}, nil)

	errCh := make(chan error, 1)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		errCh <- v.Run(ctx)
	}()

	relay.incoming <- []byte{protocol.MsgTypeControl, protocol.CtrlJoinAck, 'v', '0', '0', '0', '0', '0'}

	waitForSent(t, relay, 1)
	sent := relay.getSent()
	initMsg := sent[0]

	if len(initMsg) < 2 {
		t.Fatal("expected client type byte in SPAKE2 init")
	}
	if initMsg[1] != protocol.ClientByteCLI {
		t.Errorf("default client type byte = 0x%02x, want 0x%02x (cli)", initMsg[1], protocol.ClientByteCLI)
	}

	cancel()
	<-errCh
}

func TestSessionNotFound(t *testing.T) {
	relay := newFakeRelay()
	v := New(relay, testCode, &safeBuffer{}, nil)

	errCh := make(chan error, 1)
	go func() {
		errCh <- v.Run(context.Background())
	}()

	relay.incoming <- []byte{protocol.MsgTypeControl, protocol.CtrlSessionNotFound}

	select {
	case err := <-errCh:
		if !errors.Is(err, ErrSessionNotFound) {
			t.Errorf("expected ErrSessionNotFound, got %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("viewer did not return")
	}
}

func TestSessionEndedDuringStream(t *testing.T) {
	relay := newFakeRelay()
	probe := &recordingProbe{}

	sess, err := session.NewSession(testCode)
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()

	v := New(relay, testCode, &safeBuffer{}, probe)

	errCh := make(chan error, 1)
	ctx := context.Background()
	go func() {
		errCh <- v.Run(ctx)
	}()

	simulateSharerHandshake(t, relay, sess, testCode)
	waitForProbe(t, probe)

	relay.incoming <- []byte{protocol.MsgTypeControl, protocol.CtrlSessionEnded}

	select {
	case err := <-errCh:
		if !errors.Is(err, ErrSessionEnded) {
			t.Errorf("expected ErrSessionEnded, got %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("viewer did not return on session end")
	}

	probe.mu.Lock()
	if probe.ended == "" {
		t.Error("SessionEnded probe not called")
	}
	probe.mu.Unlock()
}

func TestHandshakeTimeout(t *testing.T) {
	relay := newFakeRelay()
	v := New(relay, testCode, &safeBuffer{}, nil)

	// Override the handshake timeout by using a short-lived context
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	// Send join ack but then don't continue the handshake
	relay.incoming <- []byte{protocol.MsgTypeControl, protocol.CtrlJoinAck, 'v', '0', '0', '0', '0', '0'}

	err := v.Run(ctx)
	if !errors.Is(err, ErrHandshakeTimeout) {
		t.Errorf("expected ErrHandshakeTimeout, got %v", err)
	}
}

func TestReplayProtection(t *testing.T) {
	relay := newFakeRelay()
	output := &safeBuffer{}
	probe := &recordingProbe{}

	sess, err := session.NewSession(testCode)
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()

	v := New(relay, testCode, output, probe)

	errCh := make(chan error, 1)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		errCh <- v.Run(ctx)
	}()

	simulateSharerHandshake(t, relay, sess, testCode)
	waitForProbe(t, probe)

	ct1, nonce1, epoch1, _ := sess.EncryptFrame([]byte("first"))
	frame1 := buildStreamFrame(ct1, nonce1, epoch1)
	relay.incoming <- frame1

	waitForOutput(t, output)

	// Replay the same frame — should be silently discarded
	output.Reset()
	relay.incoming <- frame1
	time.Sleep(50 * time.Millisecond)

	// Send a new frame to prove the viewer is still working
	ct2, nonce2, epoch2, _ := sess.EncryptFrame([]byte("second"))
	frame2 := buildStreamFrame(ct2, nonce2, epoch2)
	relay.incoming <- frame2

	waitForOutput(t, output)

	if got := output.String(); got != "second" {
		t.Errorf("output after replay = %q, want %q", got, "second")
	}

	cancel()
	<-errCh
}

func TestConnectionLost(t *testing.T) {
	relay := newFakeRelay()
	probe := &recordingProbe{}

	sess, err := session.NewSession(testCode)
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()

	v := New(relay, testCode, &safeBuffer{}, probe)

	errCh := make(chan error, 1)
	go func() {
		errCh <- v.Run(context.Background())
	}()

	simulateSharerHandshake(t, relay, sess, testCode)
	waitForProbe(t, probe)

	relay.Close()

	select {
	case err := <-errCh:
		if !errors.Is(err, ErrConnectionLost) {
			t.Errorf("expected ErrConnectionLost, got %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("viewer did not return on connection lost")
	}
}

func TestKeyMaterialZeroedOnStop(t *testing.T) {
	relay := newFakeRelay()
	probe := &recordingProbe{}

	sess, err := session.NewSession(testCode)
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()

	v := New(relay, testCode, &safeBuffer{}, probe)

	errCh := make(chan error, 1)
	ctx, cancel := context.WithCancel(context.Background())

	go func() {
		errCh <- v.Run(ctx)
	}()

	simulateSharerHandshake(t, relay, sess, testCode)
	waitForProbe(t, probe)

	// Stream key is set after handshake completes — safe to read now
	// since the viewer goroutine is blocked on relay.Recv
	keySlice := v.streamKey

	cancel()
	<-errCh

	for _, b := range keySlice {
		if b != 0 {
			t.Fatal("stream key not zeroed after stop")
		}
	}
}

// --- K' Rotation Tests ---

func TestStreamKeyRotation(t *testing.T) {
	relay := newFakeRelay()
	output := &safeBuffer{}
	probe := &recordingProbe{}

	sess, err := session.NewSession(testCode)
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()

	v := New(relay, testCode, output, probe)

	errCh := make(chan error, 1)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		errCh <- v.Run(ctx)
	}()

	hs := simulateSharerHandshake(t, relay, sess, testCode)
	defer crypto.ZeroBytes(hs.authKey)
	waitForProbe(t, probe)

	// Stream a frame under original K
	ct, nonce, epoch, err := sess.EncryptFrame([]byte("before rotation"))
	if err != nil {
		t.Fatal(err)
	}
	relay.incoming <- buildStreamFrame(ct, nonce, epoch)
	waitForOutput(t, output)

	if got := output.String(); got != "before rotation" {
		t.Fatalf("output = %q, want %q", got, "before rotation")
	}
	output.Reset()

	// Simulate K' rotation: generate new stream key, encrypt it with viewer's auth key
	kPrime, err := crypto.GenerateStreamKey()
	if err != nil {
		t.Fatal(err)
	}
	defer crypto.ZeroBytes(kPrime)

	rekeyNonce := sess.NextNonce()
	ct, err = crypto.Seal(hs.authKey, rekeyNonce, kPrime)
	if err != nil {
		t.Fatal(err)
	}

	rekeyMsg := make([]byte, protocol.ViewerIDLen+protocol.NonceLen+len(ct))
	copy(rekeyMsg[:protocol.ViewerIDLen], hs.viewerID)
	copy(rekeyMsg[protocol.ViewerIDLen:protocol.ViewerIDLen+protocol.NonceLen], rekeyNonce)
	copy(rekeyMsg[protocol.ViewerIDLen+protocol.NonceLen:], ct)

	relay.incoming <- rekeyMsg

	// Wait for the probe to record the rotation
	waitForKeyRotation(t, probe)

	// Stream a frame under K'
	epochK := uint64(time.Now().Unix()) / protocol.EpochDurationSec
	epochKey, err := crypto.DeriveEpochKey(kPrime, epochK)
	if err != nil {
		t.Fatal(err)
	}
	defer crypto.ZeroBytes(epochKey)

	frameNonce := sess.NextNonce()
	ct, err = crypto.Seal(epochKey, frameNonce, []byte("after rotation"))
	if err != nil {
		t.Fatal(err)
	}

	relay.incoming <- buildStreamFrame(ct, frameNonce, epochK)
	waitForOutput(t, output)

	if got := output.String(); got != "after rotation" {
		t.Fatalf("output after rotation = %q, want %q", got, "after rotation")
	}

	probe.mu.Lock()
	if probe.keyRotations != 1 {
		t.Errorf("keyRotations = %d, want 1", probe.keyRotations)
	}
	probe.mu.Unlock()

	cancel()
	<-errCh
}

func TestStreamKeyRotationNonceDoesNotReset(t *testing.T) {
	relay := newFakeRelay()
	output := &safeBuffer{}
	probe := &recordingProbe{}

	sess, err := session.NewSession(testCode)
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()

	v := New(relay, testCode, output, probe)

	errCh := make(chan error, 1)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		errCh <- v.Run(ctx)
	}()

	hs := simulateSharerHandshake(t, relay, sess, testCode)
	defer crypto.ZeroBytes(hs.authKey)
	waitForProbe(t, probe)

	// Stream a frame under original K — this advances the nonce
	ct, nonce, epoch, err := sess.EncryptFrame([]byte("first"))
	if err != nil {
		t.Fatal(err)
	}
	relay.incoming <- buildStreamFrame(ct, nonce, epoch)
	waitForOutput(t, output)
	output.Reset()

	// Deliver K'
	kPrime, err := crypto.GenerateStreamKey()
	if err != nil {
		t.Fatal(err)
	}
	defer crypto.ZeroBytes(kPrime)

	rekeyNonce := sess.NextNonce()
	ct, err = crypto.Seal(hs.authKey, rekeyNonce, kPrime)
	if err != nil {
		t.Fatal(err)
	}

	rekeyMsg := make([]byte, protocol.ViewerIDLen+protocol.NonceLen+len(ct))
	copy(rekeyMsg[:protocol.ViewerIDLen], hs.viewerID)
	copy(rekeyMsg[protocol.ViewerIDLen:protocol.ViewerIDLen+protocol.NonceLen], rekeyNonce)
	copy(rekeyMsg[protocol.ViewerIDLen+protocol.NonceLen:], ct)

	relay.incoming <- rekeyMsg
	waitForKeyRotation(t, probe)

	// Build a frame under K' with a LOW nonce (nonce=1) — should be rejected
	epochK := uint64(time.Now().Unix()) / protocol.EpochDurationSec
	epochKey, err := crypto.DeriveEpochKey(kPrime, epochK)
	if err != nil {
		t.Fatal(err)
	}
	defer crypto.ZeroBytes(epochKey)

	lowNonce := make([]byte, protocol.NonceLen)
	binary.BigEndian.PutUint64(lowNonce[4:], 1)
	ct, err = crypto.Seal(epochKey, lowNonce, []byte("replayed"))
	if err != nil {
		t.Fatal(err)
	}
	relay.incoming <- buildStreamFrame(ct, lowNonce, epochK)

	// Send a valid frame with a proper high nonce to prove the viewer is alive
	validNonce := sess.NextNonce()
	ct, err = crypto.Seal(epochKey, validNonce, []byte("valid"))
	if err != nil {
		t.Fatal(err)
	}
	relay.incoming <- buildStreamFrame(ct, validNonce, epochK)
	waitForOutput(t, output)

	if got := output.String(); got != "valid" {
		t.Fatalf("output = %q, want %q (replayed frame should be discarded)", got, "valid")
	}

	cancel()
	<-errCh
}

func TestRevokedViewerDetectsSustainedDecryptionFailure(t *testing.T) {
	relay := newFakeRelay()
	probe := &recordingProbe{}

	sess, err := session.NewSession(testCode)
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()

	v := New(relay, testCode, &safeBuffer{}, probe)

	errCh := make(chan error, 1)
	go func() {
		errCh <- v.Run(context.Background())
	}()

	hs := simulateSharerHandshake(t, relay, sess, testCode)
	defer crypto.ZeroBytes(hs.authKey)
	waitForProbe(t, probe)

	// Send frames encrypted under a key the viewer doesn't have (simulating K' rotation
	// where this viewer was revoked and never received K')
	unknownKey, err := crypto.GenerateStreamKey()
	if err != nil {
		t.Fatal(err)
	}
	defer crypto.ZeroBytes(unknownKey)

	epochK := uint64(time.Now().Unix()) / protocol.EpochDurationSec
	epochKey, err := crypto.DeriveEpochKey(unknownKey, epochK)
	if err != nil {
		t.Fatal(err)
	}
	defer crypto.ZeroBytes(epochKey)

	// Send enough undecryptable frames to trigger the revocation detection threshold
	for i := 0; i < protocol.ViewerRevocationFailureThreshold+1; i++ {
		nonce := make([]byte, protocol.NonceLen)
		binary.BigEndian.PutUint64(nonce[4:], uint64(100+i))
		ct, err := crypto.Seal(epochKey, nonce, []byte("secret"))
		if err != nil {
			t.Fatal(err)
		}
		relay.incoming <- buildStreamFrame(ct, nonce, epochK)
	}

	select {
	case err := <-errCh:
		if !errors.Is(err, ErrAccessRevoked) {
			t.Errorf("expected ErrAccessRevoked, got %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("viewer did not exit on sustained decryption failure")
	}

	probe.mu.Lock()
	if !probe.accessRevoked {
		t.Error("AccessRevoked probe not called")
	}
	probe.mu.Unlock()
}

func TestOldStreamKeyZeroedAfterRotation(t *testing.T) {
	relay := newFakeRelay()
	probe := &recordingProbe{}

	sess, err := session.NewSession(testCode)
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()

	v := New(relay, testCode, &safeBuffer{}, probe)

	errCh := make(chan error, 1)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		errCh <- v.Run(ctx)
	}()

	hs := simulateSharerHandshake(t, relay, sess, testCode)
	defer crypto.ZeroBytes(hs.authKey)
	waitForProbe(t, probe)

	// Capture a reference to the old key bytes
	oldKey := v.streamKey

	// Deliver K'
	kPrime, err := crypto.GenerateStreamKey()
	if err != nil {
		t.Fatal(err)
	}
	defer crypto.ZeroBytes(kPrime)

	rekeyNonce := sess.NextNonce()
	ct, err := crypto.Seal(hs.authKey, rekeyNonce, kPrime)
	if err != nil {
		t.Fatal(err)
	}

	rekeyMsg := make([]byte, protocol.ViewerIDLen+protocol.NonceLen+len(ct))
	copy(rekeyMsg[:protocol.ViewerIDLen], hs.viewerID)
	copy(rekeyMsg[protocol.ViewerIDLen:protocol.ViewerIDLen+protocol.NonceLen], rekeyNonce)
	copy(rekeyMsg[protocol.ViewerIDLen+protocol.NonceLen:], ct)

	relay.incoming <- rekeyMsg
	waitForKeyRotation(t, probe)

	// The old key bytes should now be zeroed
	for _, b := range oldKey {
		if b != 0 {
			t.Fatal("old stream key not zeroed after K' rotation")
		}
	}

	cancel()
	<-errCh
}

func TestStreamKeyRotationWrongViewerID(t *testing.T) {
	relay := newFakeRelay()
	output := &safeBuffer{}
	probe := &recordingProbe{}

	sess, err := session.NewSession(testCode)
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()

	v := New(relay, testCode, output, probe)

	errCh := make(chan error, 1)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		errCh <- v.Run(ctx)
	}()

	hs := simulateSharerHandshake(t, relay, sess, testCode)
	defer crypto.ZeroBytes(hs.authKey)
	waitForProbe(t, probe)

	// Send K' with a wrong viewer ID — should be silently rejected
	kPrime, err := crypto.GenerateStreamKey()
	if err != nil {
		t.Fatal(err)
	}
	defer crypto.ZeroBytes(kPrime)

	rekeyNonce := sess.NextNonce()
	ct, err := crypto.Seal(hs.authKey, rekeyNonce, kPrime)
	if err != nil {
		t.Fatal(err)
	}

	rekeyMsg := make([]byte, protocol.ViewerIDLen+protocol.NonceLen+len(ct))
	copy(rekeyMsg[:protocol.ViewerIDLen], "zzzzzz")
	copy(rekeyMsg[protocol.ViewerIDLen:protocol.ViewerIDLen+protocol.NonceLen], rekeyNonce)
	copy(rekeyMsg[protocol.ViewerIDLen+protocol.NonceLen:], ct)

	relay.incoming <- rekeyMsg

	// Verify viewer is still alive by streaming a valid frame under original K
	ct2, nonce2, epoch2, err := sess.EncryptFrame([]byte("still alive"))
	if err != nil {
		t.Fatal(err)
	}
	relay.incoming <- buildStreamFrame(ct2, nonce2, epoch2)
	waitForOutput(t, output)

	if got := output.String(); got != "still alive" {
		t.Fatalf("output = %q, want %q", got, "still alive")
	}

	probe.mu.Lock()
	if probe.keyRotations != 0 {
		t.Errorf("keyRotations = %d, want 0 (wrong viewer ID should be rejected)", probe.keyRotations)
	}
	probe.mu.Unlock()

	cancel()
	<-errCh
}

func TestStreamKeyRotationTamperedCiphertext(t *testing.T) {
	relay := newFakeRelay()
	output := &safeBuffer{}
	probe := &recordingProbe{}

	sess, err := session.NewSession(testCode)
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()

	v := New(relay, testCode, output, probe)

	errCh := make(chan error, 1)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		errCh <- v.Run(ctx)
	}()

	hs := simulateSharerHandshake(t, relay, sess, testCode)
	defer crypto.ZeroBytes(hs.authKey)
	waitForProbe(t, probe)

	// Send K' with tampered ciphertext — should be rejected, viewer continues with old K
	kPrime, err := crypto.GenerateStreamKey()
	if err != nil {
		t.Fatal(err)
	}
	defer crypto.ZeroBytes(kPrime)

	rekeyNonce := sess.NextNonce()
	ct, err := crypto.Seal(hs.authKey, rekeyNonce, kPrime)
	if err != nil {
		t.Fatal(err)
	}
	ct[len(ct)-1] ^= 0xff // flip a bit

	rekeyMsg := make([]byte, protocol.ViewerIDLen+protocol.NonceLen+len(ct))
	copy(rekeyMsg[:protocol.ViewerIDLen], hs.viewerID)
	copy(rekeyMsg[protocol.ViewerIDLen:protocol.ViewerIDLen+protocol.NonceLen], rekeyNonce)
	copy(rekeyMsg[protocol.ViewerIDLen+protocol.NonceLen:], ct)

	relay.incoming <- rekeyMsg

	// Viewer should still work under the original K
	ct2, nonce2, epoch2, err := sess.EncryptFrame([]byte("still working"))
	if err != nil {
		t.Fatal(err)
	}
	relay.incoming <- buildStreamFrame(ct2, nonce2, epoch2)
	waitForOutput(t, output)

	if got := output.String(); got != "still working" {
		t.Fatalf("output = %q, want %q", got, "still working")
	}

	probe.mu.Lock()
	if probe.keyRotations != 0 {
		t.Errorf("keyRotations = %d, want 0 (tampered K' should be rejected)", probe.keyRotations)
	}
	probe.mu.Unlock()

	cancel()
	<-errCh
}

func TestMultipleSequentialKeyRotations(t *testing.T) {
	relay := newFakeRelay()
	output := &safeBuffer{}
	probe := &recordingProbe{}

	sess, err := session.NewSession(testCode)
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()

	v := New(relay, testCode, output, probe)

	errCh := make(chan error, 1)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		errCh <- v.Run(ctx)
	}()

	hs := simulateSharerHandshake(t, relay, sess, testCode)
	defer crypto.ZeroBytes(hs.authKey)
	waitForProbe(t, probe)

	currentKey := make([]byte, protocol.KeyLen)
	// We don't have direct access to the original stream key from outside,
	// so we verify each rotation by streaming frames under the new key.

	for rotation := 1; rotation <= 3; rotation++ {
		kNew, err := crypto.GenerateStreamKey()
		if err != nil {
			t.Fatal(err)
		}

		rekeyNonce := sess.NextNonce()
		ct, err := crypto.Seal(hs.authKey, rekeyNonce, kNew)
		if err != nil {
			crypto.ZeroBytes(kNew)
			t.Fatal(err)
		}

		rekeyMsg := make([]byte, protocol.ViewerIDLen+protocol.NonceLen+len(ct))
		copy(rekeyMsg[:protocol.ViewerIDLen], hs.viewerID)
		copy(rekeyMsg[protocol.ViewerIDLen:protocol.ViewerIDLen+protocol.NonceLen], rekeyNonce)
		copy(rekeyMsg[protocol.ViewerIDLen+protocol.NonceLen:], ct)

		relay.incoming <- rekeyMsg

		// Wait for rotation to be processed
		deadline := time.After(5 * time.Second)
		for {
			probe.mu.Lock()
			done := probe.keyRotations >= rotation
			probe.mu.Unlock()
			if done {
				break
			}
			select {
			case <-deadline:
				t.Fatalf("rotation %d not processed", rotation)
			default:
				time.Sleep(5 * time.Millisecond)
			}
		}

		// Stream a frame under the new key
		output.Reset()
		epochK := uint64(time.Now().Unix()) / protocol.EpochDurationSec
		epochKey, err := crypto.DeriveEpochKey(kNew, epochK)
		if err != nil {
			crypto.ZeroBytes(kNew)
			t.Fatal(err)
		}

		frameNonce := sess.NextNonce()
		ct, err = crypto.Seal(epochKey, frameNonce, []byte(fmt.Sprintf("rotation-%d", rotation)))
		crypto.ZeroBytes(epochKey)
		if err != nil {
			crypto.ZeroBytes(kNew)
			t.Fatal(err)
		}

		relay.incoming <- buildStreamFrame(ct, frameNonce, epochK)
		waitForOutput(t, output)

		want := fmt.Sprintf("rotation-%d", rotation)
		if got := output.String(); got != want {
			t.Fatalf("rotation %d: output = %q, want %q", rotation, got, want)
		}

		copy(currentKey, kNew)
		crypto.ZeroBytes(kNew)
	}

	probe.mu.Lock()
	if probe.keyRotations != 3 {
		t.Errorf("keyRotations = %d, want 3", probe.keyRotations)
	}
	probe.mu.Unlock()

	cancel()
	<-errCh
}

// --- Terminal Size Tests ---

func TestViewerReceivesTerminalSize(t *testing.T) {
	relay := newFakeRelay()
	output := &safeBuffer{}
	probe := &recordingProbe{}

	sess, err := session.NewSession(testCode)
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()

	v := New(relay, testCode, output, probe)

	errCh := make(chan error, 1)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		errCh <- v.Run(ctx)
	}()

	simulateSharerHandshake(t, relay, sess, testCode)
	waitForProbe(t, probe)

	// Build and send a MsgTypeTermSize frame
	sizePlaintext := make([]byte, 4)
	binary.BigEndian.PutUint16(sizePlaintext[0:2], 120)
	binary.BigEndian.PutUint16(sizePlaintext[2:4], 40)

	ct, nonce, epoch, err := sess.EncryptFrame(sizePlaintext)
	if err != nil {
		t.Fatal(err)
	}
	relay.incoming <- buildTermSizeFrame(ct, nonce, epoch)

	waitForResize(t, probe)

	probe.mu.Lock()
	if len(probe.resizes) != 1 {
		t.Fatalf("expected 1 resize event, got %d", len(probe.resizes))
	}
	if probe.resizes[0].cols != 120 || probe.resizes[0].rows != 40 {
		t.Errorf("resize = %dx%d, want 120x40", probe.resizes[0].cols, probe.resizes[0].rows)
	}
	probe.mu.Unlock()

	if v.SharerSize().Cols != 120 || v.SharerSize().Rows != 40 {
		t.Errorf("SharerSize = %dx%d, want 120x40", v.SharerSize().Cols, v.SharerSize().Rows)
	}

	cancel()
	<-errCh
}

func TestViewerResizeCallback(t *testing.T) {
	relay := newFakeRelay()
	output := &safeBuffer{}
	probe := &recordingProbe{}

	sess, err := session.NewSession(testCode)
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()

	v := New(relay, testCode, output, probe)

	var callbackCols, callbackRows uint16
	callbackCalled := make(chan struct{}, 1)
	v.SetResizeHandler(func(cols, rows uint16) {
		callbackCols = cols
		callbackRows = rows
		select {
		case callbackCalled <- struct{}{}:
		default:
		}
	})

	errCh := make(chan error, 1)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		errCh <- v.Run(ctx)
	}()

	simulateSharerHandshake(t, relay, sess, testCode)
	waitForProbe(t, probe)

	sizePlaintext := make([]byte, 4)
	binary.BigEndian.PutUint16(sizePlaintext[0:2], 200)
	binary.BigEndian.PutUint16(sizePlaintext[2:4], 50)

	ct, nonce, epoch, err := sess.EncryptFrame(sizePlaintext)
	if err != nil {
		t.Fatal(err)
	}
	relay.incoming <- buildTermSizeFrame(ct, nonce, epoch)

	select {
	case <-callbackCalled:
	case <-time.After(5 * time.Second):
		t.Fatal("resize callback not called")
	}

	if callbackCols != 200 || callbackRows != 50 {
		t.Errorf("callback size = %dx%d, want 200x50", callbackCols, callbackRows)
	}

	cancel()
	<-errCh
}

func TestTermSizeSkippedDuringHandshake(t *testing.T) {
	relay := newFakeRelay()
	output := &safeBuffer{}
	probe := &recordingProbe{}

	sess, err := session.NewSession(testCode)
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()

	v := New(relay, testCode, output, probe)

	errCh := make(chan error, 1)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		errCh <- v.Run(ctx)
	}()

	// Send join ack
	relay.incoming <- []byte{protocol.MsgTypeControl, protocol.CtrlJoinAck, 'v', '0', '0', '0', '0', '0'}
	waitForSent(t, relay, 1)

	// Inject a MsgTypeTermSize frame mid-handshake — it should be skipped
	sizePlaintext := make([]byte, 4)
	binary.BigEndian.PutUint16(sizePlaintext[0:2], 120)
	binary.BigEndian.PutUint16(sizePlaintext[2:4], 40)
	ct, nonce, epoch, err := sess.EncryptFrame(sizePlaintext)
	if err != nil {
		t.Fatal(err)
	}
	sizeFrame := buildTermSizeFrame(ct, nonce, epoch)
	relay.incoming <- sizeFrame

	// Now complete the handshake normally
	sharerSpake, err := crypto.NewSPAKE2Sharer(testCode)
	if err != nil {
		t.Fatal(err)
	}
	defer sharerSpake.Destroy()

	msgA, err := sharerSpake.Start()
	if err != nil {
		t.Fatal(err)
	}
	relay.incoming <- msgA

	waitForSent(t, relay, 2)
	sent := relay.getSent()
	msgB := sent[1][1:]

	confirmA, err := sharerSpake.Finish(msgB)
	if err != nil {
		t.Fatal(err)
	}
	relay.incoming <- confirmA

	waitForSent(t, relay, 3)
	sent = relay.getSent()
	confirmB := sent[2][1:]

	if err := sharerSpake.Verify(confirmB); err != nil {
		t.Fatal(err)
	}

	spakeSecret, err := sharerSpake.SessionKey()
	if err != nil {
		t.Fatal(err)
	}
	defer crypto.ZeroBytes(spakeSecret)

	authKey, err := crypto.DeriveAuthKey(spakeSecret)
	if err != nil {
		t.Fatal(err)
	}

	info, encPayload, err := sess.RegisterViewer(authKey, protocol.ClientTypeCLI)
	if err != nil {
		t.Fatal(err)
	}

	delivery := make([]byte, protocol.ViewerIDLen+protocol.NonceLen+len(encPayload.Ciphertext))
	copy(delivery[:protocol.ViewerIDLen], info.ID)
	copy(delivery[protocol.ViewerIDLen:protocol.ViewerIDLen+protocol.NonceLen], encPayload.Nonce)
	copy(delivery[protocol.ViewerIDLen+protocol.NonceLen:], encPayload.Ciphertext)
	relay.incoming <- delivery

	waitForProbe(t, probe)

	// Verify handshake completed despite the injected size frame
	if probe.completed == "" {
		t.Fatal("handshake did not complete after size frame injection")
	}

	// The size frame was injected during handshake and should have been skipped
	probe.mu.Lock()
	resizeCount := len(probe.resizes)
	probe.mu.Unlock()
	if resizeCount != 0 {
		t.Errorf("expected 0 resize events during handshake, got %d", resizeCount)
	}

	cancel()
	<-errCh
}

// --- Helpers ---

func buildTermSizeFrame(ciphertext, nonce []byte, epoch uint64) []byte {
	buf := make([]byte, 1+8+protocol.NonceLen+len(ciphertext))
	buf[0] = protocol.MsgTypeTermSize
	binary.BigEndian.PutUint64(buf[1:9], epoch)
	copy(buf[9:9+protocol.NonceLen], nonce)
	copy(buf[9+protocol.NonceLen:], ciphertext)
	return buf
}

func waitForResize(t *testing.T, probe *recordingProbe) {
	t.Helper()
	deadline := time.After(5 * time.Second)
	for {
		probe.mu.Lock()
		done := len(probe.resizes) > 0
		probe.mu.Unlock()
		if done {
			return
		}
		select {
		case <-deadline:
			t.Fatal("resize not received")
		default:
			time.Sleep(5 * time.Millisecond)
		}
	}
}

func waitForKeyRotation(t *testing.T, probe *recordingProbe) {
	t.Helper()
	deadline := time.After(5 * time.Second)
	for {
		probe.mu.Lock()
		done := probe.keyRotations > 0
		probe.mu.Unlock()
		if done {
			return
		}
		select {
		case <-deadline:
			t.Fatal("K' rotation not processed")
		default:
			time.Sleep(5 * time.Millisecond)
		}
	}
}

func waitForProbe(t *testing.T, probe *recordingProbe) {
	t.Helper()
	deadline := time.After(5 * time.Second)
	for {
		probe.mu.Lock()
		done := probe.completed != ""
		probe.mu.Unlock()
		if done {
			return
		}
		select {
		case <-deadline:
			t.Fatal("handshake did not complete")
		default:
			time.Sleep(5 * time.Millisecond)
		}
	}
}

func waitForOutput(t *testing.T, output *safeBuffer) {
	t.Helper()
	deadline := time.After(5 * time.Second)
	for {
		if output.Len() > 0 {
			return
		}
		select {
		case <-deadline:
			t.Fatal("no output from viewer")
		default:
			time.Sleep(5 * time.Millisecond)
		}
	}
}

func buildStreamFrame(ciphertext, nonce []byte, epoch uint64) []byte {
	buf := make([]byte, 1+8+protocol.NonceLen+len(ciphertext))
	buf[0] = protocol.MsgTypeStream
	binary.BigEndian.PutUint64(buf[1:9], epoch)
	copy(buf[9:9+protocol.NonceLen], nonce)
	copy(buf[9+protocol.NonceLen:], ciphertext)
	return buf
}
