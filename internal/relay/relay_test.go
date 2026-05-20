package relay

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/coder/websocket"
	"github.com/jsell-rh/lockwire/internal/protocol"
)

func randomSessionID(t *testing.T) string {
	t.Helper()
	b := make([]byte, protocol.SessionIDLen)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("generating session ID: %v", err)
	}
	return hex.EncodeToString(b)
}

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
	t.Cleanup(func() { conn.CloseNow() })
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
	t.Cleanup(func() { conn.CloseNow() })
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
	sid := randomSessionID(t)
	conn := dialShare(t, ts, sid)

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
	sid := randomSessionID(t)

	conn1 := dialShare(t, ts, sid)
	_ = readMsg(t, conn1)

	conn2 := dialShare(t, ts, sid)
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
	sid := randomSessionID(t)

	sharer := dialShare(t, ts, sid)
	_ = readMsg(t, sharer)

	viewer := dialWatch(t, ts, sid)
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
	sid := randomSessionID(t)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	conn, _, err := websocket.Dial(ctx, ts.URL+"/api/watch/"+sid, nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.CloseNow()

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
	sid := randomSessionID(t)

	sharer := dialShare(t, ts, sid)
	_ = readMsg(t, sharer)

	viewerA := dialWatch(t, ts, sid)
	_ = readMsg(t, viewerA)

	viewerB := dialWatch(t, ts, sid)
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
	sid := randomSessionID(t)

	sharer := dialShare(t, ts, sid)
	_ = readMsg(t, sharer)

	viewer := dialWatch(t, ts, sid)
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
	sid := randomSessionID(t)

	sharer := dialShare(t, ts, sid)
	_ = readMsg(t, sharer)

	viewer := dialWatch(t, ts, sid)
	ack := readMsg(t, viewer)
	viewerID := string(ack[2 : 2+protocol.ViewerIDLen])

	msg := make([]byte, 1+protocol.ViewerIDLen+3)
	msg[0] = protocol.MsgTypeUnicast
	copy(msg[1:1+protocol.ViewerIDLen], viewerID)
	copy(msg[1+protocol.ViewerIDLen:], []byte{0xCA, 0xFE, 0x00})
	writeMsg(t, sharer, msg)

	got := readMsg(t, viewer)
	wantPayload := []byte{0xCA, 0xFE, 0x00}
	if string(got) != string(wantPayload) {
		t.Errorf("viewer got %x, want %x (relay should strip type+viewerID)", got, wantPayload)
	}
}

func TestHeartbeat(t *testing.T) {
	_, ts := startTestServer(t)
	sid := randomSessionID(t)

	sharer := dialShare(t, ts, sid)
	_ = readMsg(t, sharer)

	ping := []byte{protocol.MsgTypeHeartbeat}
	writeMsg(t, sharer, ping)

	pong := readMsg(t, sharer)
	if len(pong) < 1 || pong[0] != protocol.MsgTypePong {
		t.Errorf("pong = %x, want [%02x]", pong, protocol.MsgTypePong)
	}
}

func TestViewerHeartbeat(t *testing.T) {
	_, ts := startTestServer(t)
	sid := randomSessionID(t)

	sharer := dialShare(t, ts, sid)
	_ = readMsg(t, sharer)

	viewer := dialWatch(t, ts, sid)
	_ = readMsg(t, viewer)

	writeMsg(t, viewer, []byte{protocol.MsgTypeHeartbeat})
	pong := readMsg(t, viewer)
	if len(pong) < 1 || pong[0] != protocol.MsgTypePong {
		t.Errorf("viewer pong = %x, want [%02x]", pong, protocol.MsgTypePong)
	}
}

func TestSharerDisconnectNotifiesViewers(t *testing.T) {
	_, ts := startTestServer(t)
	sid := randomSessionID(t)

	sharer := dialShare(t, ts, sid)
	_ = readMsg(t, sharer)

	viewer := dialWatch(t, ts, sid)
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
	sid := randomSessionID(t)

	sharer := dialShare(t, ts, sid)
	_ = readMsg(t, sharer)

	v1 := dialWatch(t, ts, sid)
	_ = readMsg(t, v1)
	v2 := dialWatch(t, ts, sid)
	_ = readMsg(t, v2)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	v3, _, err := websocket.Dial(ctx, ts.URL+"/api/watch/"+sid, nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer v3.CloseNow()

	msg := readMsg(t, v3)
	if len(msg) < 2 {
		t.Fatalf("control frame too short: %d bytes", len(msg))
	}
	if msg[1] != protocol.CtrlSessionFull {
		t.Errorf("sub-type = 0x%02x, want 0x%02x (session-full)", msg[1], protocol.CtrlSessionFull)
	}
}

func TestViewerDisconnectDoesNotAffectOthers(t *testing.T) {
	_, ts := startTestServer(t)
	sid := randomSessionID(t)

	sharer := dialShare(t, ts, sid)
	_ = readMsg(t, sharer)

	v1 := dialWatch(t, ts, sid)
	_ = readMsg(t, v1)
	v2 := dialWatch(t, ts, sid)
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

func TestTermSizeBroadcast(t *testing.T) {
	_, ts := startTestServer(t)
	sid := randomSessionID(t)

	sharer := dialShare(t, ts, sid)
	_ = readMsg(t, sharer)

	viewerA := dialWatch(t, ts, sid)
	_ = readMsg(t, viewerA)

	viewerB := dialWatch(t, ts, sid)
	_ = readMsg(t, viewerB)

	payload := []byte{protocol.MsgTypeTermSize, 0x00, 0x78, 0x00, 0x18}
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

func TestInvalidSessionIDRejected(t *testing.T) {
	_, ts := startTestServer(t)

	cases := []struct {
		name string
		id   string
	}{
		{"too short", "abc123"},
		{"too long", "0123456789abcdef0123456789abcdef00"},
		{"not hex", "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			_, resp, err := websocket.Dial(ctx, ts.URL+"/api/share/"+tc.id, nil)
			if err == nil {
				t.Fatal("expected dial to fail for invalid session ID")
			}
			if resp != nil && resp.StatusCode != http.StatusBadRequest {
				t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusBadRequest)
			}
		})
	}
}

func TestWebViewerServedAtJoin(t *testing.T) {
	assets := fstest.MapFS{
		"dist/index.html": &fstest.MapFile{
			Data: []byte(`<!DOCTYPE html><html><body><input id="code"><button id="watch">Watch</button></body></html>`),
		},
	}
	srv := NewServer(WithWebAssets(assets))
	ts := httptest.NewServer(srv)
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/join")
	if err != nil {
		t.Fatalf("GET /join: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	ct := resp.Header.Get("Content-Type")
	if !strings.Contains(ct, "text/html") {
		t.Errorf("content-type = %q, want text/html", ct)
	}

	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), `id="code"`) {
		t.Error("HTML missing code input field")
	}
	if !strings.Contains(string(body), "Watch") {
		t.Error("HTML missing Watch button")
	}
}

func TestWebViewerServedAtRoot(t *testing.T) {
	assets := fstest.MapFS{
		"dist/index.html": &fstest.MapFile{
			Data: []byte(`<!DOCTYPE html><html><body>lockwire</body></html>`),
		},
	}
	srv := NewServer(WithWebAssets(assets))
	ts := httptest.NewServer(srv)
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/")
	if err != nil {
		t.Fatalf("GET /: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "lockwire") {
		t.Error("root route did not serve web viewer")
	}
}

func TestWebViewerNotServedWithoutAssets(t *testing.T) {
	srv := NewServer()
	ts := httptest.NewServer(srv)
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/join")
	if err != nil {
		t.Fatalf("GET /join: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		t.Errorf("expected non-200 for /join without web assets, got %d", resp.StatusCode)
	}
}

func TestAPIRoutesWorkWithWebAssets(t *testing.T) {
	assets := fstest.MapFS{
		"dist/index.html": &fstest.MapFile{Data: []byte(`<html></html>`)},
	}
	srv := NewServer(WithWebAssets(assets))
	ts := httptest.NewServer(srv)
	defer ts.Close()

	sid := randomSessionID(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	conn, _, err := websocket.Dial(ctx, ts.URL+"/api/share/"+sid, nil)
	if err != nil {
		t.Fatalf("WebSocket dial failed with web assets enabled: %v", err)
	}
	defer conn.CloseNow()

	msg := readMsg(t, conn)
	if len(msg) < 2 || msg[1] != protocol.CtrlRegistrationAck {
		t.Errorf("expected registration ack, got %x", msg)
	}
}

func TestWebViewerMissingIndexReturns404(t *testing.T) {
	assets := fstest.MapFS{
		"dist/other.html": &fstest.MapFile{Data: []byte(`<html></html>`)},
	}
	srv := NewServer(WithWebAssets(assets))
	ts := httptest.NewServer(srv)
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/join")
	if err != nil {
		t.Fatalf("GET /join: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusNotFound)
	}
}

func TestProbeReceivesAcceptError(t *testing.T) {
	var calls []string
	probe := &recordingRelayProbe{onAcceptError: func(handler string, err error) {
		calls = append(calls, handler)
	}}
	srv := NewServer(WithProbe(probe))
	ts := httptest.NewServer(srv)
	defer ts.Close()

	// A plain HTTP GET to a WebSocket endpoint triggers a websocket.Accept error.
	resp, err := http.Get(ts.URL + "/api/share/aabbccdd11223344aabbccdd11223344")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	resp.Body.Close()

	if len(calls) != 1 || calls[0] != "share" {
		t.Errorf("probe calls = %v, want [share]", calls)
	}
}

type recordingRelayProbe struct {
	onAcceptError  func(handler string, err error)
	onRateLimited  func(ip string, activity string)
	onBanTriggered func(ip string, activity string, duration string)
}

func (p *recordingRelayProbe) AcceptError(handler string, err error) {
	if p.onAcceptError != nil {
		p.onAcceptError(handler, err)
	}
}

func (p *recordingRelayProbe) RateLimited(ip string, activity string) {
	if p.onRateLimited != nil {
		p.onRateLimited(ip, activity)
	}
}

func (p *recordingRelayProbe) BanTriggered(ip string, activity string, duration string) {
	if p.onBanTriggered != nil {
		p.onBanTriggered(ip, activity, duration)
	}
}

func TestConnectionRateExceededReturns429(t *testing.T) {
	clk := newFakeClock()
	probe := &recordingRelayProbe{}
	rl := NewRateLimiter(RateLimitConfig{
		ConnectionLimit:    3,
		ConnectionWindow:   time.Minute,
		RegistrationLimit:  protocol.DefaultRegistrationRateLimit,
		RegistrationWindow: time.Minute,
		HandshakeLimit:     protocol.DefaultHandshakeRateLimit,
		HandshakeWindow:    10 * time.Minute,
	}, probe, clk.Now)

	srv := NewServer(WithRateLimiter(rl), WithProbe(probe))
	ts := httptest.NewServer(srv)
	defer ts.Close()

	sid := randomSessionID(t)
	sharer := dialShare(t, ts, sid)
	_ = readMsg(t, sharer)

	for range 3 {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		conn, _, err := websocket.Dial(ctx, ts.URL+"/api/watch/"+randomSessionID(t), nil)
		cancel()
		if err == nil {
			conn.CloseNow()
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, resp, err := websocket.Dial(ctx, ts.URL+"/api/watch/"+sid, nil)
	if err == nil {
		t.Fatal("expected dial to fail with 429")
	}
	if resp != nil && resp.StatusCode != http.StatusTooManyRequests {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusTooManyRequests)
	}
}

func TestBannedIPReturns403(t *testing.T) {
	clk := newFakeClock()
	probe := &recordingRelayProbe{}
	rl := NewRateLimiter(RateLimitConfig{
		ConnectionLimit:    2,
		ConnectionWindow:   time.Minute,
		RegistrationLimit:  protocol.DefaultRegistrationRateLimit,
		RegistrationWindow: time.Minute,
		HandshakeLimit:     protocol.DefaultHandshakeRateLimit,
		HandshakeWindow:    10 * time.Minute,
	}, probe, clk.Now)

	srv := NewServer(WithRateLimiter(rl), WithProbe(probe))
	ts := httptest.NewServer(srv)
	defer ts.Close()

	banThreshold := 2 * protocol.RateLimitBanMultiplier
	for range banThreshold {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		conn, _, err := websocket.Dial(ctx, ts.URL+"/api/watch/"+randomSessionID(t), nil)
		cancel()
		if err == nil {
			conn.CloseNow()
		}
	}

	if !rl.IsBanned("127.0.0.1") {
		t.Fatal("IP should be banned")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, resp, err := websocket.Dial(ctx, ts.URL+"/api/watch/"+randomSessionID(t), nil)
	if err == nil {
		t.Fatal("expected dial to fail with 403")
	}
	if resp != nil && resp.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusForbidden)
	}
}

func TestRegistrationRateExceededReturns429(t *testing.T) {
	clk := newFakeClock()
	rl := NewRateLimiter(RateLimitConfig{
		ConnectionLimit:    100,
		ConnectionWindow:   time.Minute,
		RegistrationLimit:  2,
		RegistrationWindow: time.Minute,
		HandshakeLimit:     protocol.DefaultHandshakeRateLimit,
		HandshakeWindow:    10 * time.Minute,
	}, &recordingRelayProbe{}, clk.Now)

	srv := NewServer(WithRateLimiter(rl))
	ts := httptest.NewServer(srv)
	defer ts.Close()

	for range 2 {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		conn, _, err := websocket.Dial(ctx, ts.URL+"/api/share/"+randomSessionID(t), nil)
		cancel()
		if err == nil {
			conn.CloseNow()
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, resp, err := websocket.Dial(ctx, ts.URL+"/api/share/"+randomSessionID(t), nil)
	if err == nil {
		t.Fatal("expected dial to fail with 429")
	}
	if resp != nil && resp.StatusCode != http.StatusTooManyRequests {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusTooManyRequests)
	}
}

func TestRateLimitDoesNotAffectOtherIPs(t *testing.T) {
	clk := newFakeClock()
	rl := NewRateLimiter(RateLimitConfig{
		ConnectionLimit:    1,
		ConnectionWindow:   time.Minute,
		RegistrationLimit:  protocol.DefaultRegistrationRateLimit,
		RegistrationWindow: time.Minute,
		HandshakeLimit:     protocol.DefaultHandshakeRateLimit,
		HandshakeWindow:    10 * time.Minute,
	}, &recordingRelayProbe{}, clk.Now)

	srv := NewServer(WithRateLimiter(rl))
	ts := httptest.NewServer(srv)
	defer ts.Close()

	sid := randomSessionID(t)
	sharer := dialShare(t, ts, sid)
	_ = readMsg(t, sharer)

	viewer := dialWatch(t, ts, sid)
	msg := readMsg(t, viewer)
	if msg[1] != protocol.CtrlJoinAck {
		t.Errorf("expected join-ack, got 0x%02x", msg[1])
	}
}

func TestNoRateLimiterAllowsUnlimited(t *testing.T) {
	srv := NewServer()
	ts := httptest.NewServer(srv)
	defer ts.Close()

	for range 30 {
		sid := randomSessionID(t)
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		conn, _, err := websocket.Dial(ctx, ts.URL+"/api/share/"+sid, nil)
		cancel()
		if err != nil {
			t.Fatalf("request should succeed without rate limiter: %v", err)
		}
		conn.CloseNow()
	}
}

func TestUnicastToNonexistentViewerSilentlyDropped(t *testing.T) {
	_, ts := startTestServer(t)
	sid := randomSessionID(t)

	sharer := dialShare(t, ts, sid)
	_ = readMsg(t, sharer)

	msg := make([]byte, 1+protocol.ViewerIDLen+3)
	msg[0] = protocol.MsgTypeUnicast
	copy(msg[1:1+protocol.ViewerIDLen], "zzzzzz")
	copy(msg[1+protocol.ViewerIDLen:], []byte{0x01, 0x02, 0x03})
	writeMsg(t, sharer, msg)

	writeMsg(t, sharer, []byte{protocol.MsgTypeHeartbeat})
	pong := readMsg(t, sharer)
	if pong[0] != protocol.MsgTypePong {
		t.Errorf("expected pong after dropped unicast, got %x", pong)
	}
}
