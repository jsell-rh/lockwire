package crypto

import (
	"crypto/rand"
	"math/big"

	"github.com/jsell-rh/lockwire/internal/protocol"
)

func GenerateViewerID() string {
	charset := protocol.ViewerIDCharset
	b := make([]byte, protocol.ViewerIDLen)
	for i := range b {
		idx, _ := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		b[i] = charset[idx.Int64()]
	}
	return string(b)
}
