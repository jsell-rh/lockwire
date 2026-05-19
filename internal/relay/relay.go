package relay

import (
	"context"
	"crypto/rand"
	"fmt"
	"log"
	"net/http"
	"sync"

	"github.com/jsell-rh/lockwire/internal/protocol"
	"github.com/coder/websocket"
)

type viewerConn struct {
	id   string
	conn *websocket.Conn
}

type session struct {
	mu      sync.Mutex
	sharer  *websocket.Conn
	viewers map[string]*viewerConn
	done    chan struct{}
}

type Server struct {
	mu         sync.Mutex
	sessions   map[string]*session
	maxViewers int
	mux        *http.ServeMux
}

func NewServer() *Server {
	s := &Server{
		sessions:   make(map[string]*session),
		maxViewers: protocol.DefaultMaxViewers,
	}
	s.mux = http.NewServeMux()
	s.mux.HandleFunc("GET /api/share/{sessionID}", s.handleShare)
	s.mux.HandleFunc("GET /api/watch/{sessionID}", s.handleWatch)
	return s
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mux.ServeHTTP(w, r)
}

func (s *Server) handleShare(w http.ResponseWriter, r *http.Request) {
	sessionID := r.PathValue("sessionID")

	conn, err := websocket.Accept(w, r, nil)
	if err != nil {
		log.Printf("relay: accept share: %v", err)
		return
	}

	s.mu.Lock()
	if _, exists := s.sessions[sessionID]; exists {
		s.mu.Unlock()
		sendControl(r.Context(), conn, protocol.CtrlSessionIDConflict, nil)
		conn.Close(websocket.StatusPolicyViolation, "session-id-conflict")
		return
	}

	sess := &session{
		sharer:  conn,
		viewers: make(map[string]*viewerConn),
		done:    make(chan struct{}),
	}
	s.sessions[sessionID] = sess
	s.mu.Unlock()

	sendControl(r.Context(), conn, protocol.CtrlRegistrationAck, nil)

	s.runSharer(sessionID, sess, conn)
}

func (s *Server) handleWatch(w http.ResponseWriter, r *http.Request) {
	sessionID := r.PathValue("sessionID")

	conn, err := websocket.Accept(w, r, nil)
	if err != nil {
		log.Printf("relay: accept watch: %v", err)
		return
	}

	s.mu.Lock()
	sess, exists := s.sessions[sessionID]
	s.mu.Unlock()

	if !exists {
		sendControl(r.Context(), conn, protocol.CtrlSessionNotFound, nil)
		conn.Close(websocket.StatusPolicyViolation, "session-not-found")
		return
	}

	sess.mu.Lock()
	if len(sess.viewers) >= s.maxViewers {
		sess.mu.Unlock()
		sendControl(r.Context(), conn, protocol.CtrlSessionFull, nil)
		conn.Close(websocket.StatusPolicyViolation, "session-full")
		return
	}

	id, err := generateViewerID()
	if err != nil {
		sess.mu.Unlock()
		conn.Close(websocket.StatusInternalError, "internal error")
		return
	}

	vc := &viewerConn{id: id, conn: conn}
	sess.viewers[id] = vc
	sess.mu.Unlock()

	sendControl(r.Context(), conn, protocol.CtrlJoinAck, []byte(id))

	s.runViewer(sess, vc)
}

func (s *Server) runSharer(sessionID string, sess *session, conn *websocket.Conn) {
	defer func() {
		sess.mu.Lock()
		for _, vc := range sess.viewers {
			sendControl(context.Background(), vc.conn, protocol.CtrlSessionEnded, nil)
			vc.conn.Close(websocket.StatusNormalClosure, "session-ended")
		}
		sess.viewers = nil
		sess.mu.Unlock()
		close(sess.done)

		s.mu.Lock()
		delete(s.sessions, sessionID)
		s.mu.Unlock()
	}()

	for {
		_, data, err := conn.Read(context.Background())
		if err != nil {
			return
		}
		if len(data) == 0 {
			continue
		}

		switch data[0] {
		case protocol.MsgTypeStream:
			sess.mu.Lock()
			for _, vc := range sess.viewers {
				_ = vc.conn.Write(context.Background(), websocket.MessageBinary, data)
			}
			sess.mu.Unlock()

		case protocol.MsgTypeUnicast:
			if len(data) < 1+protocol.ViewerIDLen {
				continue
			}
			targetID := string(data[1 : 1+protocol.ViewerIDLen])
			sess.mu.Lock()
			if vc, ok := sess.viewers[targetID]; ok {
				_ = vc.conn.Write(context.Background(), websocket.MessageBinary, data)
			}
			sess.mu.Unlock()

		case protocol.MsgTypeHeartbeat:
			_ = conn.Write(context.Background(), websocket.MessageBinary, []byte{protocol.MsgTypePong})
		}
	}
}

func (s *Server) runViewer(sess *session, vc *viewerConn) {
	defer func() {
		sess.mu.Lock()
		delete(sess.viewers, vc.id)
		sess.mu.Unlock()
	}()

	for {
		_, data, err := vc.conn.Read(context.Background())
		if err != nil {
			return
		}
		if len(data) == 0 {
			continue
		}

		switch data[0] {
		case protocol.MsgTypeSPAKE2:
			tagged := make([]byte, 1+protocol.ViewerIDLen+len(data)-1)
			tagged[0] = protocol.MsgTypeSPAKE2
			copy(tagged[1:1+protocol.ViewerIDLen], vc.id)
			copy(tagged[1+protocol.ViewerIDLen:], data[1:])
			sess.mu.Lock()
			_ = sess.sharer.Write(context.Background(), websocket.MessageBinary, tagged)
			sess.mu.Unlock()

		case protocol.MsgTypeHeartbeat:
			_ = vc.conn.Write(context.Background(), websocket.MessageBinary, []byte{protocol.MsgTypePong})
		}
	}
}

func sendControl(ctx context.Context, conn *websocket.Conn, subType byte, payload []byte) {
	msg := make([]byte, 2+len(payload))
	msg[0] = protocol.MsgTypeControl
	msg[1] = subType
	copy(msg[2:], payload)
	_ = conn.Write(ctx, websocket.MessageBinary, msg)
}

func generateViewerID() (string, error) {
	b := make([]byte, protocol.ViewerIDLen)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generating viewer ID: %w", err)
	}
	charset := protocol.ViewerIDCharset
	for i := range b {
		b[i] = charset[int(b[i])%len(charset)]
	}
	return string(b), nil
}
