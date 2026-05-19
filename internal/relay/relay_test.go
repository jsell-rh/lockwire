package relay

import (
	"context"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jsell-rh/lockwire/internal/protocol"
	"github.com/coder/websocket"
)

func startTestServer(t *testing.T) (*Server, *httptest.Server) {
	t.Helper()
	srv := NewServer()
	ts := httptest.NewServer(srv)
	t.Cleanup(ts.Close)
	return srv, ts
}

func dialShare(t *testing.T, ts *httptest.Server, sessionID string) *websocket.Conn {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	t.Cleanup(cancel)
	conn, _, err := websocket.Dial(ctx, ts.URL+"/api/share/"+sessionID, nil)
	if err != nil {
		t.Fatalf("dial share: %v", err)
	}
	t.Cleanup(func() { conn.Close(websocket.StatusNormalClosure, "") })
	return conn
}

func dialWatch(t *testing.T, ts *httptest.Server, sessionID string) *websocket.Conn {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	t.Cleanup(cancel)
	conn, _, err := websocket.Dial(ctx, ts.URL+"/api/watch/"+sessionID, nil)
	if err != nil {
		t.Fatalf("dial watch: %v", err)
	}
	t.Cleanup(func() { conn.Close(websocket.StatusNormalClosure, "") })
	return conn
}

func readMsg(t *testing.T, conn *websocket.Conn) []byte {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, data, err := conn.Read(ctx)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	return data
}

func writeMsg(t *testing.T, conn *websocket.Conn, data []byte) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := conn.Write(ctx, websocket.MessageBinary, data); err != nil {
		t.Fatalf("write: %v", err)
	}
}

func TestSharerRegistration(t *testing.T) {
	_, ts := startTestServer(t)
	conn := dialShare(t, ts, "abc123")

	msg := readMsg(t, conn)
	if len(msg) < 2 {
		t.Fatalf("control frame too short: %d bytes", len(msg))
	}
	if msg[0] != protocol.MsgTypeControl {
		t.Errorf("type = 0x%02x, want 0x%02x", msg[0], protocol.MsgTypeControl)
	}
	if msg[1] != protocol.CtrlRegistrationAck {
		t.Errorf("sub-type = 0x%02x, want 0x%02x (registration-ack)", msg[1], protocol.CtrlRegistrationAck)
	}
}

func TestDuplicateSessionID(t *testing.T) {
	_, ts := startTestServer(t)

	conn1 := dialShare(t, ts, "dup-session")
	_ = readMsg(t, conn1) // consume registration-ack

	conn2 := dialShare(t, ts, "dup-session")
	msg := readMsg(t, conn2)

	if len(msg) < 2 {
		t.Fatalf("control frame too short: %d bytes", len(msg))
	}
	if msg[0] != protocol.MsgTypeControl {
		t.Errorf("type = 0x%02x, want 0x%02x", msg[0], protocol.MsgTypeControl)
	}
	if msg[1] != protocol.CtrlSessionIDConflict {
		t.Errorf("sub-type = 0x%02x, want 0x%02x (session-id-conflict)", msg[1], protocol.CtrlSessionIDConflict)
	}
}

func TestViewerJoinsActiveSession(t *testing.T) {
	_, ts := startTestServer(t)

	sharer := dialShare(t, ts, "session-1")
	_ = readMsg(t, sharer)

	viewer := dialWatch(t, ts, "session-1")
	msg := readMsg(t, viewer)

	if len(msg) < 2+protocol.ViewerIDLen {
		t.Fatalf("join-ack too short: %d bytes", len(msg))
	}
	if msg[0] != protocol.MsgTypeControl {
		t.Errorf("type = 0x%02x, want 0x%02x", msg[0], protocol.MsgTypeControl)
	}
	if msg[1] != protocol.CtrlJoinAck {
		t.Errorf("sub-type = 0x%02x, want 0x%02x (join-ack)", msg[1], protocol.CtrlJoinAck)
	}
	viewerID := string(msg[2 : 2+protocol.ViewerIDLen])
	for _, c := range viewerID {
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') {
			t.Errorf("viewer ID %q contains invalid char %q", viewerID, string(c))
		}
	}
}

func TestViewerJoinsNonexistentSession(t *testing.T) {
	_, ts := startTestServer(t)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	conn, _, err := websocket.Dial(ctx, ts.URL+"/api/watch/no-such-session", nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close(websocket.StatusNormalClosure, "")

	msg := readMsg(t, conn)
	if len(msg) < 2 {
		t.Fatalf("control frame too short: %d bytes", len(msg))
	}
	if msg[1] != protocol.CtrlSessionNotFound {
		t.Errorf("sub-type = 0x%02x, want 0x%02x (session-not-found)", msg[1], protocol.CtrlSessionNotFound)
	}
}

func TestBlobBroadcast(t *testing.T) {
	_, ts := startTestServer(t)

	sharer := dialShare(t, ts, "broadcast-session")
	_ = readMsg(t, sharer)

	viewerA := dialWatch(t, ts, "broadcast-session")
	_ = readMsg(t, viewerA)

	viewerB := dialWatch(t, ts, "broadcast-session")
	_ = readMsg(t, viewerB)

	payload := []byte{protocol.MsgTypeStream, 0xDE, 0xAD, 0xBE, 0xEF}
	writeMsg(t, sharer, payload)

	gotA := readMsg(t, viewerA)
	gotB := readMsg(t, viewerB)

	if string(gotA) != string(payload) {
		t.Errorf("viewer A got %x, want %x", gotA, payload)
	}
	if string(gotB) != string(payload) {
		t.Errorf("viewer B got %x, want %x", gotB, payload)
	}
}

func TestSPAKE2UnicastToSharer(t *testing.T) {
	_, ts := startTestServer(t)

	sharer := dialShare(t, ts, "spake-session")
	_ = readMsg(t, sharer)

	viewer := dialWatch(t, ts, "spake-session")
	ack := readMsg(t, viewer)
	viewerID := string(ack[2 : 2+protocol.ViewerIDLen])

	spakeMsg := []byte{protocol.MsgTypeSPAKE2, 0x01, 0x02, 0x03}
	writeMsg(t, viewer, spakeMsg)

	got := readMsg(t, sharer)
	if got[0] != protocol.MsgTypeSPAKE2 {
		t.Errorf("type = 0x%02x, want 0x%02x", got[0], protocol.MsgTypeSPAKE2)
	}
	if len(got) < 1+protocol.ViewerIDLen {
		t.Fatalf("SPAKE2 forwarded msg too short: %d bytes", len(got))
	}
	gotID := string(got[1 : 1+protocol.ViewerIDLen])
	if gotID != viewerID {
		t.Errorf("viewer ID in forwarded SPAKE2 = %q, want %q", gotID, viewerID)
	}
	gotPayload := got[1+protocol.ViewerIDLen:]
	if len(gotPayload) != 3 || gotPayload[0] != 0x01 || gotPayload[1] != 0x02 || gotPayload[2] != 0x03 {
		t.Errorf("payload = %x, want 010203", gotPayload)
	}
}

func TestUnicastToViewer(t *testing.T) {
	_, ts := startTestServer(t)

	sharer := dialShare(t, ts, "unicast-session")
	_ = readMsg(t, sharer)

	viewer := dialWatch(t, ts, "unicast-session")
	ack := readMsg(t, viewer)
	viewerID := string(ack[2 : 2+protocol.ViewerIDLen])

	msg := make([]byte, 1+protocol.ViewerIDLen+3)
	msg[0] = protocol.MsgTypeUnicast
	copy(msg[1:1+protocol.ViewerIDLen], viewerID)
	copy(msg[1+protocol.ViewerIDLen:], []byte{0xCA, 0xFE, 0x00})
	writeMsg(t, sharer, msg)

	got := readMsg(t, viewer)
	if got[0] != protocol.MsgTypeUnicast {
		t.Errorf("type = 0x%02x, want 0x%02x", got[0], protocol.MsgTypeUnicast)
	}
	if string(got) != string(msg) {
		t.Errorf("viewer got %x, want %x", got, msg)
	}
}

func TestHeartbeat(t *testing.T) {
	_, ts := startTestServer(t)

	sharer := dialShare(t, ts, "hb-session")
	_ = readMsg(t, sharer)

	ping := []byte{protocol.MsgTypeHeartbeat}
	writeMsg(t, sharer, ping)

	pong := readMsg(t, sharer)
	if len(pong) < 1 || pong[0] != protocol.MsgTypePong {
		t.Errorf("pong = %x, want [%02x]", pong, protocol.MsgTypePong)
	}
}

func TestSharerDisconnectNotifiesViewers(t *testing.T) {
	_, ts := startTestServer(t)

	sharer := dialShare(t, ts, "teardown-session")
	_ = readMsg(t, sharer)

	viewer := dialWatch(t, ts, "teardown-session")
	_ = readMsg(t, viewer)

	sharer.Close(websocket.StatusNormalClosure, "done")

	msg := readMsg(t, viewer)
	if len(msg) < 2 {
		t.Fatalf("control frame too short: %d bytes", len(msg))
	}
	if msg[1] != protocol.CtrlSessionEnded {
		t.Errorf("sub-type = 0x%02x, want 0x%02x (session-ended)", msg[1], protocol.CtrlSessionEnded)
	}
}

func TestMaxViewersExceeded(t *testing.T) {
	srv, ts := startTestServer(t)
	srv.maxViewers = 2

	sharer := dialShare(t, ts, "full-session")
	_ = readMsg(t, sharer)

	v1 := dialWatch(t, ts, "full-session")
	_ = readMsg(t, v1)
	v2 := dialWatch(t, ts, "full-session")
	_ = readMsg(t, v2)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	v3, _, err := websocket.Dial(ctx, ts.URL+"/api/watch/full-session", nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer v3.Close(websocket.StatusNormalClosure, "")

	msg := readMsg(t, v3)
	if len(msg) < 2 {
		t.Fatalf("control frame too short: %d bytes", len(msg))
	}
	if msg[1] != protocol.CtrlSessionFull {
		t.Errorf("sub-type = 0x%02x, want 0x%02x (session-full)", msg[1], protocol.CtrlSessionFull)
	}
}

func TestViewerHeartbeat(t *testing.T) {
	_, ts := startTestServer(t)

	sharer := dialShare(t, ts, "vhb-session")
	_ = readMsg(t, sharer)

	viewer := dialWatch(t, ts, "vhb-session")
	_ = readMsg(t, viewer)

	writeMsg(t, viewer, []byte{protocol.MsgTypeHeartbeat})
	pong := readMsg(t, viewer)
	if len(pong) < 1 || pong[0] != protocol.MsgTypePong {
		t.Errorf("viewer pong = %x, want [%02x]", pong, protocol.MsgTypePong)
	}
}

func TestViewerDisconnectDoesNotAffectOthers(t *testing.T) {
	_, ts := startTestServer(t)

	sharer := dialShare(t, ts, "disconnect-session")
	_ = readMsg(t, sharer)

	v1 := dialWatch(t, ts, "disconnect-session")
	_ = readMsg(t, v1)
	v2 := dialWatch(t, ts, "disconnect-session")
	_ = readMsg(t, v2)

	v1.Close(websocket.StatusNormalClosure, "bye")
	time.Sleep(50 * time.Millisecond)

	payload := []byte{protocol.MsgTypeStream, 0x01, 0x02}
	writeMsg(t, sharer, payload)

	got := readMsg(t, v2)
	if string(got) != string(payload) {
		t.Errorf("v2 got %x, want %x", got, payload)
	}
}
