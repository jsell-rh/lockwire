package viewer

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
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
	mu         sync.Mutex
	connecting bool
	completed  string
	frames     []int
	ended      string
	hsFailed   error
	heartbeats int
}

func (p *recordingProbe) Connecting()                    { p.mu.Lock(); p.connecting = true; p.mu.Unlock() }
func (p *recordingProbe) HandshakeCompleted(id string)   { p.mu.Lock(); p.completed = id; p.mu.Unlock() }
func (p *recordingProbe) FrameDecrypted(_ uint64, n int) { p.mu.Lock(); p.frames = append(p.frames, n); p.mu.Unlock() }
func (p *recordingProbe) SessionEnded(reason string)     { p.mu.Lock(); p.ended = reason; p.mu.Unlock() }
func (p *recordingProbe) HandshakeFailed(err error)      { p.mu.Lock(); p.hsFailed = err; p.mu.Unlock() }
func (p *recordingProbe) HeartbeatSent()                 { p.mu.Lock(); p.heartbeats++; p.mu.Unlock() }

// --- Sharer-side handshake helper ---

// simulateSharerHandshake runs the sharer side of the SPAKE2 handshake
// against the viewer's messages on the fake relay. It registers the viewer
// on the session and delivers the stream key.
func simulateSharerHandshake(t *testing.T, relay *fakeRelay, sess *session.Session, code []byte) {
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
	defer crypto.ZeroBytes(authKey)

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

// --- Helpers ---

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
