package crypto

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"

	"github.com/jsell-rh/lockwire/internal/protocol"
	"golang.org/x/crypto/hkdf"
)

func DeriveEpochKey(k []byte, epoch uint64) ([]byte, error) {
	info := make([]byte, len(protocol.EpochKeyInfoPrefix)+8)
	copy(info, protocol.EpochKeyInfoPrefix)
	binary.BigEndian.PutUint64(info[len(protocol.EpochKeyInfoPrefix):], epoch)

	reader := hkdf.New(sha256.New, k, nil, info)
	ek, err := NewSecureBuffer(protocol.KeyLen)
	if err != nil {
		return nil, fmt.Errorf("allocating epoch key: %w", err)
	}
	if _, err := io.ReadFull(reader, ek); err != nil {
		ZeroBytes(ek)
		return nil, fmt.Errorf("deriving epoch key %d: %w", epoch, err)
	}
	return ek, nil
}
