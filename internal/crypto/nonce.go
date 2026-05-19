package crypto

import (
	"encoding/binary"
	"sync/atomic"

	"github.com/jsell-rh/lockwire/internal/protocol"
)

type NonceCounter struct {
	val atomic.Uint64
}

func NewNonceCounter() *NonceCounter {
	return &NonceCounter{}
}

func (nc *NonceCounter) Next() []byte {
	v := nc.val.Add(1)
	nonce := make([]byte, protocol.NonceLen)
	binary.BigEndian.PutUint64(nonce[4:], v)
	return nonce
}

func (nc *NonceCounter) Current() uint64 {
	return nc.val.Load()
}
