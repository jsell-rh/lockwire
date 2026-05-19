package session

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/jsell-rh/lockwire/internal/crypto"
	"github.com/jsell-rh/lockwire/internal/protocol"
)

var (
	ErrViewerNotFound = errors.New("viewer not found")
	ErrSessionClosed  = errors.New("session closed")
)

type viewer struct {
	id         string
	authKey    []byte
	joinTime   time.Time
	clientType string
}

type ViewerInfo struct {
	ID         string
	JoinTime   time.Time
	ClientType string
}

type EncryptedPayload struct {
	Nonce      []byte
	Ciphertext []byte
}

type Session struct {
	mu         sync.RWMutex
	streamKey  []byte
	sessionID  string
	nonce      *crypto.NonceCounter
	viewers    map[string]*viewer
	revokedIDs map[string]bool
	clock      func() time.Time
	closed     bool
}

type Option func(*Session)

func WithClock(clock func() time.Time) Option {
	return func(s *Session) {
		s.clock = clock
	}
}

func NewSession(opts ...Option) (*Session, error) {
	k, err := crypto.GenerateStreamKey()
	if err != nil {
		return nil, fmt.Errorf("creating session: %w", err)
	}

	s := &Session{
		streamKey:  k,
		sessionID:  crypto.DeriveSessionID(k),
		nonce:      crypto.NewNonceCounter(),
		viewers:    make(map[string]*viewer),
		revokedIDs: make(map[string]bool),
		clock:      time.Now,
	}

	for _, opt := range opts {
		opt(s)
	}

	return s, nil
}

func (s *Session) SessionID() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.sessionID
}

func (s *Session) RegisterViewer(authKey []byte, clientType string) (ViewerInfo, EncryptedPayload, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return ViewerInfo{}, EncryptedPayload{}, ErrSessionClosed
	}

	id, err := crypto.GenerateViewerID()
	if err != nil {
		return ViewerInfo{}, EncryptedPayload{}, fmt.Errorf("generating viewer ID: %w", err)
	}

	secureCopy, err := crypto.NewSecureBuffer(len(authKey))
	if err != nil {
		return ViewerInfo{}, EncryptedPayload{}, fmt.Errorf("allocating auth key: %w", err)
	}
	copy(secureCopy, authKey)

	nonce := s.nonce.Next()
	ct, err := crypto.Seal(authKey, nonce, s.streamKey)
	if err != nil {
		crypto.ZeroBytes(secureCopy)
		return ViewerInfo{}, EncryptedPayload{}, fmt.Errorf("encrypting stream key: %w", err)
	}

	now := s.clock()
	s.viewers[id] = &viewer{
		id:         id,
		authKey:    secureCopy,
		joinTime:   now,
		clientType: clientType,
	}

	info := ViewerInfo{
		ID:         id,
		JoinTime:   now,
		ClientType: clientType,
	}

	return info, EncryptedPayload{Nonce: nonce, Ciphertext: ct}, nil
}

func (s *Session) ListViewers() []ViewerInfo {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make([]ViewerInfo, 0, len(s.viewers))
	for _, v := range s.viewers {
		result = append(result, ViewerInfo{
			ID:         v.id,
			JoinTime:   v.joinTime,
			ClientType: v.clientType,
		})
	}
	return result
}

func (s *Session) RevokeViewer(viewerID string) (map[string]EncryptedPayload, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return nil, ErrSessionClosed
	}

	revoked, ok := s.viewers[viewerID]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrViewerNotFound, viewerID)
	}

	crypto.ZeroBytes(revoked.authKey)
	delete(s.viewers, viewerID)
	s.revokedIDs[viewerID] = true

	kPrime, err := crypto.GenerateStreamKey()
	if err != nil {
		return nil, fmt.Errorf("generating new stream key: %w", err)
	}

	rekeys := make(map[string]EncryptedPayload, len(s.viewers))
	for id, v := range s.viewers {
		nonce := s.nonce.Next()
		ct, err := crypto.Seal(v.authKey, nonce, kPrime)
		if err != nil {
			crypto.ZeroBytes(kPrime)
			return nil, fmt.Errorf("encrypting K' for viewer %s: %w", id, err)
		}
		rekeys[id] = EncryptedPayload{Nonce: nonce, Ciphertext: ct}
	}

	crypto.ZeroBytes(s.streamKey)
	s.streamKey = kPrime
	s.sessionID = crypto.DeriveSessionID(kPrime)

	return rekeys, nil
}

func (s *Session) RemoveViewer(viewerID string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if v, ok := s.viewers[viewerID]; ok {
		crypto.ZeroBytes(v.authKey)
		delete(s.viewers, viewerID)
	}
}

func (s *Session) CurrentEpoch() uint64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return uint64(s.clock().Unix()) / protocol.EpochDurationSec
}

func (s *Session) EncryptFrame(plaintext []byte) (ciphertext, nonce []byte, epoch uint64, err error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.closed {
		return nil, nil, 0, ErrSessionClosed
	}

	epoch = uint64(s.clock().Unix()) / protocol.EpochDurationSec
	epochKey, err := crypto.DeriveEpochKey(s.streamKey, epoch)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("deriving epoch key: %w", err)
	}
	defer crypto.ZeroBytes(epochKey)

	nonce = s.nonce.Next()
	ciphertext, err = crypto.Seal(epochKey, nonce, plaintext)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("encrypting frame: %w", err)
	}

	return ciphertext, nonce, epoch, nil
}

func (s *Session) WasRevoked(viewerID string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.revokedIDs[viewerID]
}

func (s *Session) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return
	}

	crypto.ZeroBytes(s.streamKey)
	for _, v := range s.viewers {
		crypto.ZeroBytes(v.authKey)
	}
	s.viewers = nil
	s.closed = true
}
