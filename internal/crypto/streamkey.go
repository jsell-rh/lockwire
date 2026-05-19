package crypto

import (
	"crypto/rand"
	"fmt"

	"github.com/jsell-rh/lockwire/internal/protocol"
)

func GenerateStreamKey() ([]byte, error) {
	k, err := NewSecureBuffer(protocol.KeyLen)
	if err != nil {
		return nil, fmt.Errorf("allocating stream key: %w", err)
	}
	if _, err := rand.Read(k); err != nil {
		ZeroBytes(k)
		return nil, fmt.Errorf("generating stream key: %w", err)
	}
	return k, nil
}
