package sharer

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/jsell-rh/lockwire/internal/crypto"
	"github.com/jsell-rh/lockwire/internal/protocol"
	"github.com/jsell-rh/lockwire/internal/session"
)

type RelayConn interface {
	Send(ctx context.Context, msg []byte) error
	Recv(ctx context.Context) ([]byte, error)
	Close() error
}

type Config struct {
	Code     []byte
	RelayURL string
	Probe    Probe
}

type Sharer struct {
	sess       *session.Session
	relay      RelayConn
	code       []byte
	probe      Probe
	handshakes map[string]*handshakeCtx
	mu         sync.Mutex
	done       chan struct{}
	cancel     context.CancelFunc
	termCols   uint16
	termRows   uint16
}

type handshakeState int

const (
	hsWaitInit     handshakeState = iota
	hsWaitMsgB
	hsWaitConfirmB
	hsComplete
)

type handshakeCtx struct {
	state      handshakeState
	spake      *crypto.SPAKEHandshake
	viewerID   string
	clientType string
}

func New(sess *session.Session, relay RelayConn, code []byte, probe Probe) *Sharer {
	if probe == nil {
		probe = noopProbe{}
	}
	return &Sharer{
		sess:       sess,
		relay:      relay,
		code:       code,
		probe:      probe,
		handshakes: make(map[string]*handshakeCtx),
		done:       make(chan struct{}),
	}
}

func (s *Sharer) Run(ctx context.Context, output io.Reader) error {
	ctx, s.cancel = context.WithCancel(ctx)
	defer close(s.done)
	defer s.destroyPendingHandshakes()

	errCh := make(chan error, 2)

	go func() {
		errCh <- s.relayLoop(ctx)
	}()
	go func() {
		errCh <- s.streamLoop(ctx, output)
	}()
	go s.heartbeatLoop(ctx)

	err := <-errCh
	s.cancel()
	<-errCh

	if ctx.Err() != nil {
		s.probe.SessionTerminated("cancelled")
		return nil
	}
	return err
}

func (s *Sharer) Stop() {
	if s.cancel != nil {
		s.cancel()
	}
	<-s.done
}

func (s *Sharer) Revoke(ctx context.Context, viewerID string) error {
	rekeys, err := s.sess.RevokeViewer(viewerID)
	if err != nil {
		return err
	}

	for id, enc := range rekeys {
		delivery := buildKeyDelivery(id, enc)
		if err := s.sendUnicast(ctx, id, delivery); err != nil {
			return fmt.Errorf("delivering rekey to %s: %w", id, err)
		}
	}

	s.probe.ViewerRevoked(viewerID)
	return nil
}

func (s *Sharer) SetTermSize(ctx context.Context, cols, rows uint16) error {
	s.mu.Lock()
	s.termCols = cols
	s.termRows = rows
	s.mu.Unlock()

	return s.broadcastTermSize(ctx, cols, rows)
}

func (s *Sharer) broadcastTermSize(ctx context.Context, cols, rows uint16) error {
	plaintext := make([]byte, 4)
	binary.BigEndian.PutUint16(plaintext[0:2], cols)
	binary.BigEndian.PutUint16(plaintext[2:4], rows)

	ct, nonce, epoch, err := s.sess.EncryptFrame(plaintext)
	if err != nil {
		return fmt.Errorf("encrypting terminal size: %w", err)
	}

	frame := buildTermSizeFrame(ct, nonce, epoch)
	if err := s.relay.Send(ctx, frame); err != nil {
		return fmt.Errorf("broadcasting terminal size: %w", err)
	}

	s.probe.TerminalSizeBroadcast(cols, rows)
	return nil
}

func (s *Sharer) relayLoop(ctx context.Context) error {
	for {
		data, err := s.relay.Recv(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("reading from relay: %w", err)
		}
		if len(data) == 0 {
			continue
		}

		switch data[0] {
		case protocol.MsgTypeSPAKE2:
			if len(data) < 1+protocol.ViewerIDLen {
				continue
			}
			viewerID := string(data[1 : 1+protocol.ViewerIDLen])
			payload := data[1+protocol.ViewerIDLen:]
			if err := s.handleSPAKE2(ctx, viewerID, payload); err != nil {
				s.probe.HandshakeFailed(viewerID, err)
			}

		case protocol.MsgTypePong:
			// heartbeat response, nothing to do

		case protocol.MsgTypeControl:
			if len(data) >= 2 && data[1] == protocol.CtrlRegistrationAck {
				s.probe.RelayConnected("")
			}
		}
	}
}

func (s *Sharer) handleSPAKE2(ctx context.Context, relayViewerID string, payload []byte) error {
	s.mu.Lock()
	hs, exists := s.handshakes[relayViewerID]
	if !exists {
		spake, err := crypto.NewSPAKE2Sharer(s.code)
		if err != nil {
			s.mu.Unlock()
			return fmt.Errorf("creating SPAKE2: %w", err)
		}
		hs = &handshakeCtx{
			state:      hsWaitInit,
			spake:      spake,
			viewerID:   relayViewerID,
			clientType: clientTypeFromByte(payload),
		}
		s.handshakes[relayViewerID] = hs
	}
	s.mu.Unlock()

	switch hs.state {
	case hsWaitInit:
		msgA, err := hs.spake.Start()
		if err != nil {
			return fmt.Errorf("SPAKE2 start: %w", err)
		}
		if err := s.sendUnicast(ctx, relayViewerID, msgA); err != nil {
			return fmt.Errorf("sending SPAKE2 msg_a: %w", err)
		}
		hs.state = hsWaitMsgB

	case hsWaitMsgB:
		confirmA, err := hs.spake.Finish(payload)
		if err != nil {
			s.cleanupHandshake(relayViewerID)
			return fmt.Errorf("SPAKE2 finish: %w", err)
		}
		if err := s.sendUnicast(ctx, relayViewerID, confirmA); err != nil {
			return fmt.Errorf("sending SPAKE2 confirm_a: %w", err)
		}
		hs.state = hsWaitConfirmB

	case hsWaitConfirmB:
		if err := hs.spake.Verify(payload); err != nil {
			s.cleanupHandshake(relayViewerID)
			return fmt.Errorf("SPAKE2 verify: %w", err)
		}

		spakeSecret, err := hs.spake.SessionKey()
		if err != nil {
			s.cleanupHandshake(relayViewerID)
			return fmt.Errorf("SPAKE2 session key: %w", err)
		}
		defer crypto.ZeroBytes(spakeSecret)

		authKey, err := crypto.DeriveAuthKey(spakeSecret)
		if err != nil {
			s.cleanupHandshake(relayViewerID)
			return fmt.Errorf("deriving auth key: %w", err)
		}
		defer crypto.ZeroBytes(authKey)

		info, encPayload, err := s.sess.RegisterViewer(authKey, hs.clientType)
		if err != nil {
			s.cleanupHandshake(relayViewerID)
			return fmt.Errorf("registering viewer: %w", err)
		}

		delivery := buildKeyDelivery(info.ID, encPayload)
		if err := s.sendUnicast(ctx, relayViewerID, delivery); err != nil {
			return fmt.Errorf("sending key delivery: %w", err)
		}

		hs.state = hsComplete
		s.probe.ViewerJoined(info.ID, hs.clientType)

		s.mu.Lock()
		cols, rows := s.termCols, s.termRows
		s.mu.Unlock()
		if cols > 0 && rows > 0 {
			_ = s.broadcastTermSize(ctx, cols, rows)
		}
	}
	return nil
}

func (s *Sharer) cleanupHandshake(relayViewerID string) {
	s.mu.Lock()
	if hs, ok := s.handshakes[relayViewerID]; ok {
		hs.spake.Destroy()
		delete(s.handshakes, relayViewerID)
	}
	s.mu.Unlock()
}

func (s *Sharer) destroyPendingHandshakes() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, hs := range s.handshakes {
		hs.spake.Destroy()
		delete(s.handshakes, id)
	}
}

func (s *Sharer) sendUnicast(ctx context.Context, viewerID string, payload []byte) error {
	msg := make([]byte, 1+protocol.ViewerIDLen+len(payload))
	msg[0] = protocol.MsgTypeUnicast
	copy(msg[1:1+protocol.ViewerIDLen], viewerID)
	copy(msg[1+protocol.ViewerIDLen:], payload)
	return s.relay.Send(ctx, msg)
}

func buildKeyDelivery(sessionViewerID string, enc session.EncryptedPayload) []byte {
	// Format: viewerID(6) + nonce(12) + ciphertext
	buf := make([]byte, protocol.ViewerIDLen+protocol.NonceLen+len(enc.Ciphertext))
	copy(buf[0:protocol.ViewerIDLen], sessionViewerID)
	copy(buf[protocol.ViewerIDLen:protocol.ViewerIDLen+protocol.NonceLen], enc.Nonce)
	copy(buf[protocol.ViewerIDLen+protocol.NonceLen:], enc.Ciphertext)
	return buf
}

func (s *Sharer) streamLoop(ctx context.Context, output io.Reader) error {
	buf := make([]byte, 16384)
	for {
		n, err := output.Read(buf)
		if n > 0 {
			ct, nonce, epoch, encErr := s.sess.EncryptFrame(buf[:n])
			if encErr != nil {
				return fmt.Errorf("encrypting frame: %w", encErr)
			}
			frame := buildStreamFrame(ct, nonce, epoch)
			if sendErr := s.relay.Send(ctx, frame); sendErr != nil {
				if ctx.Err() != nil {
					return nil
				}
				return fmt.Errorf("sending stream frame: %w", sendErr)
			}
			s.probe.FrameStreamed(epoch, n)
		}
		if err != nil {
			if err == io.EOF || ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("reading terminal output: %w", err)
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

func buildTermSizeFrame(ciphertext, nonce []byte, epoch uint64) []byte {
	buf := make([]byte, 1+8+protocol.NonceLen+len(ciphertext))
	buf[0] = protocol.MsgTypeTermSize
	binary.BigEndian.PutUint64(buf[1:9], epoch)
	copy(buf[9:9+protocol.NonceLen], nonce)
	copy(buf[9+protocol.NonceLen:], ciphertext)
	return buf
}

func clientTypeFromByte(payload []byte) string {
	if len(payload) > 0 && payload[0] == protocol.ClientByteBrowser {
		return protocol.ClientTypeBrowser
	}
	return protocol.ClientTypeCLI
}

func (s *Sharer) heartbeatLoop(ctx context.Context) {
	ticker := time.NewTicker(time.Duration(protocol.HeartbeatIntervalSec) * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := s.relay.Send(ctx, []byte{protocol.MsgTypeHeartbeat}); err != nil {
				return
			}
			s.probe.HeartbeatSent()
		}
	}
}
