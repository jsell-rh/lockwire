package crypto

import (
	"crypto/sha256"
	"fmt"
	"io"

	"github.com/jsell-rh/lockwire/internal/protocol"
	"golang.org/x/crypto/hkdf"
)

func DeriveAuthKey(spakeSecret []byte) ([]byte, error) {
	reader := hkdf.New(sha256.New, spakeSecret, nil, []byte(protocol.AuthKeyInfo))
	ak, err := NewSecureBuffer(protocol.KeyLen)
	if err != nil {
		return nil, fmt.Errorf("allocating auth key: %w", err)
	}
	if _, err := io.ReadFull(reader, ak); err != nil {
		ZeroBytes(ak)
		return nil, fmt.Errorf("deriving auth key: %w", err)
	}
	return ak, nil
}
