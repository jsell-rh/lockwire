package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"

	"github.com/jsell-rh/lockwire/internal/protocol"
)

func Seal(key, nonce, plaintext []byte) ([]byte, error) {
	if len(key) != protocol.KeyLen {
		return nil, fmt.Errorf("key length %d, want %d", len(key), protocol.KeyLen)
	}
	if len(nonce) != protocol.NonceLen {
		return nil, fmt.Errorf("nonce length %d, want %d", len(nonce), protocol.NonceLen)
	}
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	return gcm.Seal(nil, nonce, plaintext, nil), nil
}

func Open(key, nonce, ciphertext []byte) ([]byte, error) {
	if len(key) != protocol.KeyLen {
		return nil, fmt.Errorf("key length %d, want %d", len(key), protocol.KeyLen)
	}
	if len(nonce) != protocol.NonceLen {
		return nil, fmt.Errorf("nonce length %d, want %d", len(nonce), protocol.NonceLen)
	}
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %w", err)
	}
	return plaintext, nil
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("creating AES cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("creating GCM: %w", err)
	}
	return gcm, nil
}
