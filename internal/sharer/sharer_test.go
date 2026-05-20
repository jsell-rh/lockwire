package sharer

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/jsell-rh/lockwire/internal/crypto"
	"github.com/jsell-rh/lockwire/internal/protocol"
	"github.com/jsell-rh/lockwire/internal/session"
)

// --- Fake relay connection ---

type fakeRelay struct {
	mu       sync.Mutex
	incoming chan []byte // messages to the sharer (from relay/viewers)
	sent     [][]byte   // messages from the sharer (to relay/viewers)
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
	cp := make([]byte, len(msg))
	copy(cp, msg)
	f.sent = append(f.sent, cp)
	return nil
}

func (f *fakeRelay) Recv(ctx context.Context) ([]byte, error) {
	select {
	case msg := <-f.incoming:
		return msg, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (f *fakeRelay) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.closed = true
	return nil
}

func (f *fakeRelay) sentMessages() [][]byte {
	f.mu.Lock()
	defer f.mu.Unlock()
	cp := make([][]byte, len(f.sent))
	for i, m := range f.sent {
		cp[i] = make([]byte, len(m))
		copy(cp[i], m)
	}
	return cp
}

// --- Recording probe ---

type joinEvent struct {
	id, clientType string
}

type recordingProbe struct {
	mu               sync.Mutex
	sessionsCreated  []string
	relayConnected   []string
	viewersJoined    []string
	viewerJoinEvents []joinEvent
	viewersLeft      []string
	viewersRevoked   []string
	framesStreamed   int
	terminated       []string
	handshakeFailed  []string
	heartbeats       int
	sizeBroadcasts   []sizeEvent
}

type sizeEvent struct {
	cols, rows uint16
}

func (p *recordingProbe) SessionCreated(sid, code string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.sessionsCreated = append(p.sessionsCreated, sid)
}

func (p *recordingProbe) RelayConnected(url string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.relayConnected = append(p.relayConnected, url)
}

func (p *recordingProbe) ViewerJoined(id, clientType string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.viewersJoined = append(p.viewersJoined, id)
	p.viewerJoinEvents = append(p.viewerJoinEvents, joinEvent{id, clientType})
}

func (p *recordingProbe) ViewerLeft(id string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.viewersLeft = append(p.viewersLeft, id)
}

func (p *recordingProbe) ViewerRevoked(id string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.viewersRevoked = append(p.viewersRevoked, id)
}

func (p *recordingProbe) FrameStreamed(epoch uint64, size int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.framesStreamed++
}

func (p *recordingProbe) SessionTerminated(reason string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.terminated = append(p.terminated, reason)
}

func (p *recordingProbe) HandshakeFailed(id string, err error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.handshakeFailed = append(p.handshakeFailed, id+": "+err.Error())
}

func (p *recordingProbe) HeartbeatSent() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.heartbeats++
}

func (p *recordingProbe) TerminalSizeBroadcast(cols, rows uint16) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.sizeBroadcasts = append(p.sizeBroadcasts, sizeEvent{cols, rows})
}

// --- Helpers ---

func buildSPAKE2Msg(viewerID string, payload []byte) []byte {
	msg := make([]byte, 1+protocol.ViewerIDLen+len(payload))
	msg[0] = protocol.MsgTypeSPAKE2
	copy(msg[1:1+protocol.ViewerIDLen], padViewerID(viewerID))
	copy(msg[1+protocol.ViewerIDLen:], payload)
	return msg
}

func padViewerID(id string) string {
	for len(id) < protocol.ViewerIDLen {
		id += "0"
	}
	return id[:protocol.ViewerIDLen]
}

func extractUnicastPayload(msg []byte) (viewerID string, payload []byte) {
	if len(msg) < 1+protocol.ViewerIDLen {
		return "", nil
	}
	return string(msg[1 : 1+protocol.ViewerIDLen]), msg[1+protocol.ViewerIDLen:]
}

// --- Tests ---

func TestSharerStreamsEncryptedFrames(t *testing.T) {
	sess, err := session.NewSession([]byte("thunder-eagle-river-moon-stone-fire"))
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	defer sess.Close()

	relay := newFakeRelay()
	probe := &recordingProbe{}

	code := []byte("test-code")
	sh := New(sess, relay, code, probe)

	output := bytes.NewReader([]byte("hello world"))

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- sh.Run(ctx, output)
	}()

	time.Sleep(100 * time.Millisecond)
	cancel()
	<-done

	msgs := relay.sentMessages()
	var streamFrames int
	for _, msg := range msgs {
		if len(msg) > 0 && msg[0] == protocol.MsgTypeStream {
			streamFrames++
		}
	}

	if streamFrames == 0 {
		t.Fatal("expected at least one stream frame")
	}

	// Verify frame structure: type(1) + epoch(8) + nonce(12) + ciphertext
	for _, msg := range msgs {
		if len(msg) == 0 || msg[0] != protocol.MsgTypeStream {
			continue
		}
		if len(msg) < 1+8+protocol.NonceLen {
			t.Errorf("stream frame too short: %d bytes", len(msg))
		}
	}

	probe.mu.Lock()
	if probe.framesStreamed == 0 {
		t.Error("expected FrameStreamed probe event")
	}
	probe.mu.Unlock()
}

func TestSharerSPAKE2Handshake(t *testing.T) {
	sess, err := session.NewSession([]byte("thunder-eagle-river-moon-stone-fire"))
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	defer sess.Close()

	relay := newFakeRelay()
	probe := &recordingProbe{}
	code := []byte("test-handshake-code")

	sh := New(sess, relay, code, probe)

	pr, pw := io.Pipe()
	defer pr.Close()
	defer pw.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() {
		done <- sh.Run(ctx, pr)
	}()

	time.Sleep(50 * time.Millisecond)

	relayViewerID := padViewerID("vw1")

	// Helper to find the nth unicast to this viewer.
	nthUnicast := func(n int) []byte {
		msgs := relay.sentMessages()
		count := 0
		for _, m := range msgs {
			if len(m) > 0 && m[0] == protocol.MsgTypeUnicast {
				vid, _ := extractUnicastPayload(m)
				if vid == relayViewerID {
					if count == n {
						return m
					}
					count++
				}
			}
		}
		return nil
	}

	// Step 1: Viewer sends init (empty payload).
	relay.incoming <- buildSPAKE2Msg(relayViewerID, nil)
	time.Sleep(50 * time.Millisecond)

	msgAUnicast := nthUnicast(0)
	if msgAUnicast == nil {
		t.Fatal("expected sharer to send SPAKE2 msg_a as unicast")
	}
	_, msgA := extractUnicastPayload(msgAUnicast)

	// Step 2: Viewer creates SPAKE2 instance and exchanges.
	viewer, err := crypto.NewSPAKE2Viewer(code)
	if err != nil {
		t.Fatalf("NewSPAKE2Viewer: %v", err)
	}

	msgB, err := viewer.Exchange(msgA)
	if err != nil {
		t.Fatalf("viewer.Exchange: %v", err)
	}

	relay.incoming <- buildSPAKE2Msg(relayViewerID, msgB)
	time.Sleep(50 * time.Millisecond)

	// Step 3: Sharer sends confirm_a (2nd unicast).
	confirmAMsg := nthUnicast(1)
	if confirmAMsg == nil {
		t.Fatal("expected sharer to send confirm_a")
	}
	_, confirmA := extractUnicastPayload(confirmAMsg)

	confirmB, err := viewer.Confirm(confirmA)
	if err != nil {
		t.Fatalf("viewer.Confirm: %v", err)
	}

	relay.incoming <- buildSPAKE2Msg(relayViewerID, confirmB)
	time.Sleep(50 * time.Millisecond)

	// Step 4: Sharer verifies and sends key delivery (3rd unicast).
	keyDeliveryMsg := nthUnicast(2)
	if keyDeliveryMsg == nil {
		t.Fatal("expected key delivery unicast")
	}
	_, delivery := extractUnicastPayload(keyDeliveryMsg)

	if len(delivery) < protocol.ViewerIDLen+protocol.NonceLen+1 {
		t.Fatalf("key delivery too short: %d bytes", len(delivery))
	}

	sessionViewerID := string(delivery[:protocol.ViewerIDLen])
	nonce := delivery[protocol.ViewerIDLen : protocol.ViewerIDLen+protocol.NonceLen]
	ciphertext := delivery[protocol.ViewerIDLen+protocol.NonceLen:]

	viewerSpakeSecret, err := viewer.SessionKey()
	if err != nil {
		t.Fatalf("viewer.SessionKey: %v", err)
	}

	viewerAuthKey, err := crypto.DeriveAuthKey(viewerSpakeSecret)
	if err != nil {
		t.Fatalf("DeriveAuthKey: %v", err)
	}

	streamKey, err := crypto.Open(viewerAuthKey, nonce, ciphertext)
	if err != nil {
		t.Fatalf("decrypting stream key: %v", err)
	}

	if len(streamKey) != protocol.KeyLen {
		t.Errorf("stream key length = %d, want %d", len(streamKey), protocol.KeyLen)
	}

	if sessionViewerID == "" {
		t.Error("expected non-empty session viewer ID")
	}

	viewers := sess.ListViewers()
	if len(viewers) != 1 {
		t.Fatalf("expected 1 viewer, got %d", len(viewers))
	}
	if viewers[0].ID != sessionViewerID {
		t.Errorf("viewer ID = %q, want %q", viewers[0].ID, sessionViewerID)
	}

	probe.mu.Lock()
	if len(probe.viewersJoined) != 1 {
		t.Errorf("expected 1 ViewerJoined event, got %d", len(probe.viewersJoined))
	}
	probe.mu.Unlock()

	pw.Close()
	cancel()
	<-done
}

func TestSharerHandshakeRecordsClientType(t *testing.T) {
	tests := []struct {
		name       string
		clientByte []byte
		wantType   string
	}{
		{"cli viewer", []byte{protocol.ClientByteCLI}, protocol.ClientTypeCLI},
		{"browser viewer", []byte{protocol.ClientByteBrowser}, protocol.ClientTypeBrowser},
		{"no client byte defaults to cli", nil, protocol.ClientTypeCLI},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sess, err := session.NewSession([]byte("thunder-eagle-river-moon-stone-fire"))
			if err != nil {
				t.Fatalf("NewSession: %v", err)
			}
			defer sess.Close()

			relay := newFakeRelay()
			probe := &recordingProbe{}
			code := []byte("test-client-type")

			sh := New(sess, relay, code, probe)

			pr, pw := io.Pipe()
			defer pr.Close()
			defer pw.Close()

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			done := make(chan error, 1)
			go func() {
				done <- sh.Run(ctx, pr)
			}()
			time.Sleep(50 * time.Millisecond)

			relayViewerID := padViewerID("vw1")

			nthUnicast := func(n int) []byte {
				msgs := relay.sentMessages()
				count := 0
				for _, m := range msgs {
					if len(m) > 0 && m[0] == protocol.MsgTypeUnicast {
						vid, _ := extractUnicastPayload(m)
						if vid == relayViewerID {
							if count == n {
								return m
							}
							count++
						}
					}
				}
				return nil
			}

			// Step 1: Viewer sends init with client type byte.
			relay.incoming <- buildSPAKE2Msg(relayViewerID, tt.clientByte)
			time.Sleep(50 * time.Millisecond)

			msgAUnicast := nthUnicast(0)
			if msgAUnicast == nil {
				t.Fatal("expected sharer to send SPAKE2 msg_a")
			}
			_, msgA := extractUnicastPayload(msgAUnicast)

			viewer, err := crypto.NewSPAKE2Viewer(code)
			if err != nil {
				t.Fatalf("NewSPAKE2Viewer: %v", err)
			}

			msgB, err := viewer.Exchange(msgA)
			if err != nil {
				t.Fatalf("viewer.Exchange: %v", err)
			}

			relay.incoming <- buildSPAKE2Msg(relayViewerID, msgB)
			time.Sleep(50 * time.Millisecond)

			confirmAMsg := nthUnicast(1)
			if confirmAMsg == nil {
				t.Fatal("expected confirm_a")
			}
			_, confirmA := extractUnicastPayload(confirmAMsg)

			confirmB, err := viewer.Confirm(confirmA)
			if err != nil {
				t.Fatalf("viewer.Confirm: %v", err)
			}

			relay.incoming <- buildSPAKE2Msg(relayViewerID, confirmB)
			time.Sleep(50 * time.Millisecond)

			// Verify the client type was recorded in the session and probe.
			viewers := sess.ListViewers()
			if len(viewers) != 1 {
				t.Fatalf("expected 1 viewer, got %d", len(viewers))
			}
			if viewers[0].ClientType != tt.wantType {
				t.Errorf("session viewer client type = %q, want %q", viewers[0].ClientType, tt.wantType)
			}

			probe.mu.Lock()
			if len(probe.viewerJoinEvents) != 1 {
				t.Fatalf("expected 1 join event, got %d", len(probe.viewerJoinEvents))
			}
			if probe.viewerJoinEvents[0].clientType != tt.wantType {
				t.Errorf("probe client type = %q, want %q", probe.viewerJoinEvents[0].clientType, tt.wantType)
			}
			probe.mu.Unlock()

			pw.Close()
			cancel()
			<-done
		})
	}
}

func TestSharerCancelStopsCleanly(t *testing.T) {
	sess, err := session.NewSession([]byte("thunder-eagle-river-moon-stone-fire"))
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	defer sess.Close()

	relay := newFakeRelay()
	sh := New(sess, relay, []byte("code"), nil)

	pr, pw := io.Pipe()
	defer pr.Close()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- sh.Run(ctx, pr)
	}()

	time.Sleep(50 * time.Millisecond)
	pw.Close()
	cancel()

	select {
	case err := <-done:
		if err != nil {
			t.Errorf("expected nil error on cancel, got: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not stop within 2 seconds of cancel")
	}
}

func TestStreamFrameFormat(t *testing.T) {
	ct := []byte("ciphertext-data")
	nonce := make([]byte, protocol.NonceLen)
	nonce[11] = 0x42
	var epoch uint64 = 1234

	frame := buildStreamFrame(ct, nonce, epoch)

	if frame[0] != protocol.MsgTypeStream {
		t.Errorf("type byte = 0x%02x, want 0x%02x", frame[0], protocol.MsgTypeStream)
	}

	gotEpoch := binary.BigEndian.Uint64(frame[1:9])
	if gotEpoch != epoch {
		t.Errorf("epoch = %d, want %d", gotEpoch, epoch)
	}

	gotNonce := frame[9 : 9+protocol.NonceLen]
	if !bytes.Equal(gotNonce, nonce) {
		t.Errorf("nonce mismatch")
	}

	gotCt := frame[9+protocol.NonceLen:]
	if !bytes.Equal(gotCt, ct) {
		t.Errorf("ciphertext mismatch")
	}
}

func TestKeyDeliveryFormat(t *testing.T) {
	viewerID := "a3k9x7"
	nonce := make([]byte, protocol.NonceLen)
	ct := []byte("encrypted-key-material")

	delivery := buildKeyDelivery(viewerID, session.EncryptedPayload{
		Nonce:      nonce,
		Ciphertext: ct,
	})

	gotID := string(delivery[:protocol.ViewerIDLen])
	if gotID != viewerID {
		t.Errorf("viewer ID = %q, want %q", gotID, viewerID)
	}

	gotNonce := delivery[protocol.ViewerIDLen : protocol.ViewerIDLen+protocol.NonceLen]
	if !bytes.Equal(gotNonce, nonce) {
		t.Error("nonce mismatch")
	}

	gotCt := delivery[protocol.ViewerIDLen+protocol.NonceLen:]
	if !bytes.Equal(gotCt, ct) {
		t.Error("ciphertext mismatch")
	}
}

func TestSharerRevokeRemovesViewerAndSendsRekey(t *testing.T) {
	sess, err := session.NewSession([]byte("thunder-eagle-river-moon-stone-fire"))
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	defer sess.Close()

	relay := newFakeRelay()
	probe := &recordingProbe{}
	sh := New(sess, relay, []byte("code"), probe)

	pr, pw := io.Pipe()
	defer pr.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() {
		done <- sh.Run(ctx, pr)
	}()
	time.Sleep(50 * time.Millisecond)

	authKeyA := make([]byte, protocol.KeyLen)
	authKeyA[0] = 0x01
	infoA, _, err := sess.RegisterViewer(authKeyA, protocol.ClientTypeCLI)
	if err != nil {
		t.Fatalf("RegisterViewer A: %v", err)
	}

	authKeyB := make([]byte, protocol.KeyLen)
	authKeyB[0] = 0x02
	_, _, err = sess.RegisterViewer(authKeyB, protocol.ClientTypeBrowser)
	if err != nil {
		t.Fatalf("RegisterViewer B: %v", err)
	}

	if err := sh.Revoke(ctx, infoA.ID); err != nil {
		t.Fatalf("Revoke: %v", err)
	}

	viewers := sess.ListViewers()
	if len(viewers) != 1 {
		t.Fatalf("expected 1 viewer after revoke, got %d", len(viewers))
	}

	// Verify rekey unicast was sent to the remaining viewer.
	msgs := relay.sentMessages()
	var rekeyFound bool
	for _, m := range msgs {
		if len(m) > 0 && m[0] == protocol.MsgTypeUnicast {
			vid, _ := extractUnicastPayload(m)
			if vid != padViewerID(infoA.ID) {
				rekeyFound = true
			}
		}
	}
	if !rekeyFound {
		t.Error("expected a rekey unicast to the remaining viewer")
	}

	probe.mu.Lock()
	if len(probe.viewersRevoked) != 1 || probe.viewersRevoked[0] != infoA.ID {
		t.Errorf("expected ViewerRevoked for %s, got %v", infoA.ID, probe.viewersRevoked)
	}
	probe.mu.Unlock()

	pw.Close()
	cancel()
	<-done
}

func TestSetTermSizeBroadcastsFrame(t *testing.T) {
	sess, err := session.NewSession([]byte("thunder-eagle-river-moon-stone-fire"))
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	defer sess.Close()

	relay := newFakeRelay()
	probe := &recordingProbe{}
	sh := New(sess, relay, []byte("code"), probe)

	pr, pw := io.Pipe()
	defer pr.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() {
		done <- sh.Run(ctx, pr)
	}()
	time.Sleep(50 * time.Millisecond)

	if err := sh.SetTermSize(ctx, 120, 40); err != nil {
		t.Fatalf("SetTermSize: %v", err)
	}

	msgs := relay.sentMessages()
	var sizeFrames int
	for _, msg := range msgs {
		if len(msg) > 0 && msg[0] == protocol.MsgTypeTermSize {
			sizeFrames++
			// Verify frame structure: type(1) + epoch(8) + nonce(12) + ciphertext
			if len(msg) < 1+8+protocol.NonceLen+protocol.GCMTagLen+4 {
				t.Errorf("size frame too short: %d bytes", len(msg))
			}
		}
	}
	if sizeFrames != 1 {
		t.Errorf("expected 1 size frame, got %d", sizeFrames)
	}

	probe.mu.Lock()
	if len(probe.sizeBroadcasts) != 1 {
		t.Errorf("expected 1 TerminalSizeBroadcast, got %d", len(probe.sizeBroadcasts))
	} else if probe.sizeBroadcasts[0].cols != 120 || probe.sizeBroadcasts[0].rows != 40 {
		t.Errorf("broadcast size = %dx%d, want 120x40", probe.sizeBroadcasts[0].cols, probe.sizeBroadcasts[0].rows)
	}
	probe.mu.Unlock()

	pw.Close()
	cancel()
	<-done
}

func TestSizeBroadcastAfterHandshake(t *testing.T) {
	sess, err := session.NewSession([]byte("thunder-eagle-river-moon-stone-fire"))
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	defer sess.Close()

	relay := newFakeRelay()
	probe := &recordingProbe{}
	code := []byte("test-handshake-code")

	sh := New(sess, relay, code, probe)

	pr, pw := io.Pipe()
	defer pr.Close()
	defer pw.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() {
		done <- sh.Run(ctx, pr)
	}()
	time.Sleep(50 * time.Millisecond)

	// Set terminal size before any viewer joins
	if err := sh.SetTermSize(ctx, 200, 50); err != nil {
		t.Fatalf("SetTermSize: %v", err)
	}

	relay.mu.Lock()
	relay.sent = nil // clear sent messages
	relay.mu.Unlock()

	// Complete a SPAKE2 handshake
	relayViewerID := padViewerID("vw1")

	nthUnicast := func(n int) []byte {
		msgs := relay.sentMessages()
		count := 0
		for _, m := range msgs {
			if len(m) > 0 && m[0] == protocol.MsgTypeUnicast {
				vid, _ := extractUnicastPayload(m)
				if vid == relayViewerID {
					if count == n {
						return m
					}
					count++
				}
			}
		}
		return nil
	}

	relay.incoming <- buildSPAKE2Msg(relayViewerID, nil)
	time.Sleep(50 * time.Millisecond)

	msgAUnicast := nthUnicast(0)
	if msgAUnicast == nil {
		t.Fatal("expected sharer to send SPAKE2 msg_a")
	}
	_, msgA := extractUnicastPayload(msgAUnicast)

	viewer, err := crypto.NewSPAKE2Viewer(code)
	if err != nil {
		t.Fatalf("NewSPAKE2Viewer: %v", err)
	}

	msgB, err := viewer.Exchange(msgA)
	if err != nil {
		t.Fatalf("viewer.Exchange: %v", err)
	}

	relay.incoming <- buildSPAKE2Msg(relayViewerID, msgB)
	time.Sleep(50 * time.Millisecond)

	confirmAMsg := nthUnicast(1)
	if confirmAMsg == nil {
		t.Fatal("expected sharer to send confirm_a")
	}
	_, confirmA := extractUnicastPayload(confirmAMsg)

	confirmB, err := viewer.Confirm(confirmA)
	if err != nil {
		t.Fatalf("viewer.Confirm: %v", err)
	}

	relay.incoming <- buildSPAKE2Msg(relayViewerID, confirmB)
	time.Sleep(100 * time.Millisecond)

	// After handshake completes, the sharer should have broadcast a size frame
	msgs := relay.sentMessages()
	var sizeFrames int
	for _, msg := range msgs {
		if len(msg) > 0 && msg[0] == protocol.MsgTypeTermSize {
			sizeFrames++
		}
	}
	if sizeFrames == 0 {
		t.Error("expected a MsgTypeTermSize broadcast after handshake completion")
	}

	pw.Close()
	cancel()
	<-done
}

func TestTermSizeFrameFormat(t *testing.T) {
	ct := []byte("encrypted-size")
	nonce := make([]byte, protocol.NonceLen)
	nonce[11] = 0x42
	var epoch uint64 = 99

	frame := buildTermSizeFrame(ct, nonce, epoch)

	if frame[0] != protocol.MsgTypeTermSize {
		t.Errorf("type byte = 0x%02x, want 0x%02x", frame[0], protocol.MsgTypeTermSize)
	}

	gotEpoch := binary.BigEndian.Uint64(frame[1:9])
	if gotEpoch != epoch {
		t.Errorf("epoch = %d, want %d", gotEpoch, epoch)
	}

	gotNonce := frame[9 : 9+protocol.NonceLen]
	if !bytes.Equal(gotNonce, nonce) {
		t.Errorf("nonce mismatch")
	}

	gotCt := frame[9+protocol.NonceLen:]
	if !bytes.Equal(gotCt, ct) {
		t.Errorf("ciphertext mismatch")
	}
}

func TestSharerRevokeUnknownViewerReturnsError(t *testing.T) {
	sess, err := session.NewSession([]byte("thunder-eagle-river-moon-stone-fire"))
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	defer sess.Close()

	relay := newFakeRelay()
	sh := New(sess, relay, []byte("code"), nil)

	pr, pw := io.Pipe()
	defer pr.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() {
		done <- sh.Run(ctx, pr)
	}()
	time.Sleep(50 * time.Millisecond)

	err = sh.Revoke(ctx, "nonexistent")
	if err == nil {
		t.Fatal("expected error for unknown viewer")
	}

	pw.Close()
	cancel()
	<-done
}
