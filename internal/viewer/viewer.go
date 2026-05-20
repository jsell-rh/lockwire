package viewer

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/jsell-rh/lockwire/internal/crypto"
	"github.com/jsell-rh/lockwire/internal/protocol"
)

var (
	ErrSessionNotFound  = errors.New("session not found")
	ErrSessionFull      = errors.New("session full")
	ErrHandshakeTimeout = errors.New("handshake timed out")
	ErrSessionEnded     = errors.New("session ended by sharer")
	ErrConnectionLost   = errors.New("session lost (connection dropped)")
	ErrAccessRevoked    = errors.New("access revoked")
)

type RelayConn interface {
	Send(ctx context.Context, msg []byte) error
	Recv(ctx context.Context) ([]byte, error)
	Close() error
}

type TermSize struct {
	Cols uint16
	Rows uint16
}

type Viewer struct {
	relay              RelayConn
	code               []byte
	output             io.Writer
	probe              Probe
	streamKey          []byte
	authKey            []byte
	viewerID           string
	clientTypeByte     byte
	lastNonce          uint64
	consecutiveFailures int
	done               chan struct{}
	cancel             context.CancelFunc
	sharerSize         TermSize
	onResize           func(cols, rows uint16)
}

type Option func(*Viewer)

func WithClientType(b byte) Option {
	return func(v *Viewer) {
		v.clientTypeByte = b
	}
}

func New(relay RelayConn, code []byte, output io.Writer, probe Probe, opts ...Option) *Viewer {
	if probe == nil {
		probe = noopProbe{}
	}
	v := &Viewer{
		relay:          relay,
		code:           code,
		output:         output,
		probe:          probe,
		clientTypeByte: protocol.ClientByteCLI,
		done:           make(chan struct{}),
	}
	for _, opt := range opts {
		opt(v)
	}
	return v
}

func (v *Viewer) SetResizeHandler(fn func(cols, rows uint16)) {
	v.onResize = fn
}

func (v *Viewer) SharerSize() TermSize {
	return v.sharerSize
}

func (v *Viewer) Run(ctx context.Context) error {
	ctx, v.cancel = context.WithCancel(ctx)
	defer close(v.done)
	defer v.zeroKeys()

	v.probe.Connecting()

	if err := v.handshake(ctx); err != nil {
		return err
	}

	go v.heartbeatLoop(ctx)

	return v.streamLoop(ctx)
}

func (v *Viewer) Stop() {
	if v.cancel != nil {
		v.cancel()
	}
	<-v.done
}

func (v *Viewer) handshake(ctx context.Context) error {
	hsCtx, hsCancel := context.WithTimeout(ctx, 15*time.Second)
	defer hsCancel()

	if err := v.waitForJoinAck(hsCtx); err != nil {
		return err
	}

	spake, err := crypto.NewSPAKE2Viewer(v.code)
	if err != nil {
		return fmt.Errorf("creating SPAKE2: %w", err)
	}
	defer spake.Destroy()

	if err := v.relay.Send(hsCtx, []byte{protocol.MsgTypeSPAKE2, v.clientTypeByte}); err != nil {
		return fmt.Errorf("sending SPAKE2 init: %w", err)
	}

	// Receive msg_a from sharer (unicast, no type prefix)
	msgA, err := v.recvHandshakeMsg(hsCtx)
	if err != nil {
		return err
	}

	// Exchange: process msg_a, produce msg_b
	msgB, err := spake.Exchange(msgA)
	if err != nil {
		v.probe.HandshakeFailed(err)
		return fmt.Errorf("SPAKE2 exchange: %w", err)
	}

	// Send msg_b
	if err := v.sendSPAKE2(hsCtx, msgB); err != nil {
		return fmt.Errorf("sending SPAKE2 msg_b: %w", err)
	}

	// Receive confirm_a from sharer
	confirmA, err := v.recvHandshakeMsg(hsCtx)
	if err != nil {
		return err
	}

	// Confirm: process confirm_a, produce confirm_b
	confirmB, err := spake.Confirm(confirmA)
	if err != nil {
		v.probe.HandshakeFailed(err)
		return fmt.Errorf("SPAKE2 confirm: %w", err)
	}

	// Send confirm_b
	if err := v.sendSPAKE2(hsCtx, confirmB); err != nil {
		return fmt.Errorf("sending SPAKE2 confirm_b: %w", err)
	}

	// Receive key delivery
	delivery, err := v.recvHandshakeMsg(hsCtx)
	if err != nil {
		return err
	}

	if err := v.processKeyDelivery(spake, delivery); err != nil {
		v.probe.HandshakeFailed(err)
		return err
	}

	v.probe.HandshakeCompleted(v.viewerID)
	return nil
}

func (v *Viewer) waitForJoinAck(ctx context.Context) error {
	for {
		data, err := v.relay.Recv(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return ErrHandshakeTimeout
			}
			return fmt.Errorf("waiting for join ack: %w", err)
		}
		if len(data) < 2 || data[0] != protocol.MsgTypeControl {
			continue
		}
		switch data[1] {
		case protocol.CtrlJoinAck:
			return nil
		case protocol.CtrlSessionNotFound:
			return ErrSessionNotFound
		case protocol.CtrlSessionFull:
			return ErrSessionFull
		}
	}
}

func (v *Viewer) recvHandshakeMsg(ctx context.Context) ([]byte, error) {
	for {
		data, err := v.relay.Recv(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return nil, ErrHandshakeTimeout
			}
			return nil, fmt.Errorf("receiving handshake message: %w", err)
		}
		if len(data) == 0 {
			continue
		}

		switch data[0] {
		case protocol.MsgTypeStream:
			continue
		case protocol.MsgTypeTermSize:
			continue
		case protocol.MsgTypePong:
			continue
		case protocol.MsgTypeControl:
			if len(data) >= 2 {
				switch data[1] {
				case protocol.CtrlSessionEnded:
					return nil, ErrSessionEnded
				case protocol.CtrlSessionNotFound:
					return nil, ErrSessionNotFound
				}
			}
			continue
		default:
			return data, nil
		}
	}
}

func (v *Viewer) sendSPAKE2(ctx context.Context, payload []byte) error {
	msg := make([]byte, 1+len(payload))
	msg[0] = protocol.MsgTypeSPAKE2
	copy(msg[1:], payload)
	return v.relay.Send(ctx, msg)
}

func (v *Viewer) processKeyDelivery(spake *crypto.SPAKEHandshake, delivery []byte) error {
	minLen := protocol.ViewerIDLen + protocol.NonceLen + 1
	if len(delivery) < minLen {
		return fmt.Errorf("key delivery too short: %d bytes", len(delivery))
	}

	v.viewerID = string(delivery[:protocol.ViewerIDLen])
	nonce := delivery[protocol.ViewerIDLen : protocol.ViewerIDLen+protocol.NonceLen]
	ciphertext := delivery[protocol.ViewerIDLen+protocol.NonceLen:]

	spakeSecret, err := spake.SessionKey()
	if err != nil {
		return fmt.Errorf("SPAKE2 session key: %w", err)
	}
	defer crypto.ZeroBytes(spakeSecret)

	authKey, err := crypto.DeriveAuthKey(spakeSecret)
	if err != nil {
		return fmt.Errorf("deriving auth key: %w", err)
	}

	k, err := crypto.Open(authKey, nonce, ciphertext)
	if err != nil {
		crypto.ZeroBytes(authKey)
		return fmt.Errorf("decrypting stream key: %w", err)
	}

	v.streamKey = k
	v.authKey = authKey
	return nil
}

func (v *Viewer) streamLoop(ctx context.Context) error {
	for {
		data, err := v.relay.Recv(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return ErrConnectionLost
		}
		if len(data) == 0 {
			continue
		}

		switch data[0] {
		case protocol.MsgTypeStream:
			if err := v.decryptAndWrite(data); err != nil {
				v.consecutiveFailures++
				if v.consecutiveFailures >= protocol.ViewerRevocationFailureThreshold {
					v.probe.AccessRevoked()
					return ErrAccessRevoked
				}
				continue
			}
			v.consecutiveFailures = 0
		case protocol.MsgTypeTermSize:
			v.decryptAndApplySize(data)
		case protocol.MsgTypeControl:
			if len(data) >= 2 && data[1] == protocol.CtrlSessionEnded {
				v.probe.SessionEnded("sharer disconnected")
				return ErrSessionEnded
			}
		case protocol.MsgTypePong:
			continue
		default:
			if err := v.processRekey(data); err != nil {
				continue
			}
		}
	}
}

func (v *Viewer) processRekey(data []byte) error {
	minLen := protocol.ViewerIDLen + protocol.NonceLen + protocol.GCMTagLen + 1
	if len(data) < minLen {
		return fmt.Errorf("rekey message too short: %d bytes", len(data))
	}

	id := string(data[:protocol.ViewerIDLen])
	if id != v.viewerID {
		return fmt.Errorf("rekey viewer ID mismatch: %s != %s", id, v.viewerID)
	}

	nonce := data[protocol.ViewerIDLen : protocol.ViewerIDLen+protocol.NonceLen]
	ciphertext := data[protocol.ViewerIDLen+protocol.NonceLen:]

	kPrime, err := crypto.Open(v.authKey, nonce, ciphertext)
	if err != nil {
		return fmt.Errorf("decrypting K': %w", err)
	}

	crypto.ZeroBytes(v.streamKey)
	v.streamKey = kPrime
	v.consecutiveFailures = 0
	v.probe.StreamKeyRotated()
	return nil
}

func (v *Viewer) decryptAndWrite(frame []byte) error {
	// Frame format: type(1) + epoch(8) + nonce(12) + ciphertext
	headerLen := 1 + 8 + protocol.NonceLen
	if len(frame) < headerLen+protocol.GCMTagLen {
		return fmt.Errorf("frame too short: %d bytes", len(frame))
	}

	epoch := binary.BigEndian.Uint64(frame[1:9])
	nonce := frame[9 : 9+protocol.NonceLen]
	ciphertext := frame[9+protocol.NonceLen:]

	// Replay protection: reject frames with non-increasing nonce
	var nonceVal uint64
	for i := 4; i < 12; i++ {
		nonceVal = nonceVal<<8 | uint64(nonce[i])
	}
	if nonceVal <= v.lastNonce {
		return fmt.Errorf("replayed nonce: %d <= %d", nonceVal, v.lastNonce)
	}
	v.lastNonce = nonceVal

	epochKey, err := crypto.DeriveEpochKey(v.streamKey, epoch)
	if err != nil {
		return fmt.Errorf("deriving epoch key: %w", err)
	}
	defer crypto.ZeroBytes(epochKey)

	plaintext, err := crypto.Open(epochKey, nonce, ciphertext)
	if err != nil {
		return fmt.Errorf("decrypting frame: %w", err)
	}

	v.output.Write(plaintext)
	v.probe.FrameDecrypted(epoch, len(plaintext))
	return nil
}

func (v *Viewer) decryptAndApplySize(frame []byte) {
	headerLen := 1 + 8 + protocol.NonceLen
	if len(frame) < headerLen+protocol.GCMTagLen+4 {
		return
	}

	epoch := binary.BigEndian.Uint64(frame[1:9])
	nonce := frame[9 : 9+protocol.NonceLen]
	ciphertext := frame[9+protocol.NonceLen:]

	epochKey, err := crypto.DeriveEpochKey(v.streamKey, epoch)
	if err != nil {
		return
	}
	defer crypto.ZeroBytes(epochKey)

	plaintext, err := crypto.Open(epochKey, nonce, ciphertext)
	if err != nil {
		return
	}

	if len(plaintext) < 4 {
		return
	}

	cols := binary.BigEndian.Uint16(plaintext[0:2])
	rows := binary.BigEndian.Uint16(plaintext[2:4])

	v.sharerSize = TermSize{Cols: cols, Rows: rows}
	v.probe.TerminalResized(cols, rows)

	if v.onResize != nil {
		v.onResize(cols, rows)
	}
}

func (v *Viewer) heartbeatLoop(ctx context.Context) {
	ticker := time.NewTicker(time.Duration(protocol.HeartbeatIntervalSec) * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := v.relay.Send(ctx, []byte{protocol.MsgTypeHeartbeat}); err != nil {
				return
			}
			v.probe.HeartbeatSent()
		}
	}
}

func (v *Viewer) zeroKeys() {
	if v.streamKey != nil {
		crypto.ZeroBytes(v.streamKey)
	}
	if v.authKey != nil {
		crypto.ZeroBytes(v.authKey)
	}
}
