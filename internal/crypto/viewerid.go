package crypto

import (
	"crypto/rand"
	"fmt"
	"math/big"

	"github.com/jsell-rh/lockwire/internal/protocol"
)

func GenerateViewerID() (string, error) {
	charset := protocol.ViewerIDCharset
	b := make([]byte, protocol.ViewerIDLen)
	for i := range b {
		idx, err := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		if err != nil {
			return "", fmt.Errorf("generating viewer ID: %w", err)
		}
		b[i] = charset[idx.Int64()]
	}
	return string(b), nil
}
