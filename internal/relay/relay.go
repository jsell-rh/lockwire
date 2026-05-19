package relay

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"sync"
	"time"

	"github.com/coder/websocket"
	"github.com/jsell-rh/lockwire/internal/protocol"
)

const viewerSendBufSize = 64

type viewerConn struct {
	id   string
	conn *websocket.Conn
	send chan []byte
}

type session struct {
	mu      sync.Mutex
	sharer  *websocket.Conn
	viewers map[string]*viewerConn
	closed  bool
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

func validSessionID(id string) bool {
	if len(id) != protocol.SessionIDLen*2 {
		return false
	}
	_, err := hex.DecodeString(id)
	return err == nil
}

func (s *Server) handleShare(w http.ResponseWriter, r *http.Request) {
	sessionID := r.PathValue("sessionID")
	if !validSessionID(sessionID) {
		http.Error(w, "invalid session ID", http.StatusBadRequest)
		return
	}

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
	}
	s.sessions[sessionID] = sess
	s.mu.Unlock()

	sendControl(r.Context(), conn, protocol.CtrlRegistrationAck, nil)

	s.runSharer(sessionID, sess, conn)
}

func (s *Server) handleWatch(w http.ResponseWriter, r *http.Request) {
	sessionID := r.PathValue("sessionID")
	if !validSessionID(sessionID) {
		http.Error(w, "invalid session ID", http.StatusBadRequest)
		return
	}

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
	if sess.closed {
		sess.mu.Unlock()
		sendControl(r.Context(), conn, protocol.CtrlSessionNotFound, nil)
		conn.Close(websocket.StatusPolicyViolation, "session-not-found")
		return
	}

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

	vc := &viewerConn{id: id, conn: conn, send: make(chan []byte, viewerSendBufSize)}
	sess.viewers[id] = vc
	sess.mu.Unlock()

	sendControl(r.Context(), conn, protocol.CtrlJoinAck, []byte(id))

	go s.viewerWriter(vc)
	s.runViewer(sess, vc)
}

func (s *Server) viewerWriter(vc *viewerConn) {
	for msg := range vc.send {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		err := vc.conn.Write(ctx, websocket.MessageBinary, msg)
		cancel()
		if err != nil {
			vc.conn.Close(websocket.StatusGoingAway, "write error")
			for range vc.send {
			}
			return
		}
	}
}

func (s *Server) runSharer(sessionID string, sess *session, conn *websocket.Conn) {
	defer func() {
		sess.mu.Lock()
		sess.closed = true
		for _, vc := range sess.viewers {
			sendControl(context.Background(), vc.conn, protocol.CtrlSessionEnded, nil)
			close(vc.send)
		}
		sess.viewers = nil
		sess.mu.Unlock()

		s.mu.Lock()
		delete(s.sessions, sessionID)
		s.mu.Unlock()
	}()

	timeout := time.Duration(protocol.SharerTimeoutSec) * time.Second
	for {
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		_, data, err := conn.Read(ctx)
		cancel()
		if err != nil {
			return
		}
		if len(data) == 0 {
			continue
		}

		switch data[0] {
		case protocol.MsgTypeStream:
			sess.mu.Lock()
			for id, vc := range sess.viewers {
				select {
				case vc.send <- data:
				default:
					close(vc.send)
					vc.conn.Close(websocket.StatusPolicyViolation, "slow consumer")
					delete(sess.viewers, id)
				}
			}
			sess.mu.Unlock()

		case protocol.MsgTypeUnicast:
			if len(data) < 1+protocol.ViewerIDLen {
				continue
			}
			targetID := string(data[1 : 1+protocol.ViewerIDLen])
			sess.mu.Lock()
			if vc, ok := sess.viewers[targetID]; ok {
				select {
				case vc.send <- data:
				default:
					close(vc.send)
					vc.conn.Close(websocket.StatusPolicyViolation, "slow consumer")
					delete(sess.viewers, targetID)
				}
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
		if _, ok := sess.viewers[vc.id]; ok {
			close(vc.send)
			delete(sess.viewers, vc.id)
		}
		sess.mu.Unlock()
	}()

	timeout := time.Duration(protocol.ViewerTimeoutSec) * time.Second
	for {
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		_, data, err := vc.conn.Read(ctx)
		cancel()
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
			if !sess.closed {
				_ = sess.sharer.Write(context.Background(), websocket.MessageBinary, tagged)
			}
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
	charset := protocol.ViewerIDCharset
	max := big.NewInt(int64(len(charset)))
	b := make([]byte, protocol.ViewerIDLen)
	for i := range b {
		n, err := rand.Int(rand.Reader, max)
		if err != nil {
			return "", fmt.Errorf("generating viewer ID: %w", err)
		}
		b[i] = charset[n.Int64()]
	}
	return string(b), nil
}
