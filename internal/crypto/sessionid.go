package crypto

import (
	"encoding/hex"

	"github.com/jsell-rh/lockwire/internal/protocol"
	"golang.org/x/crypto/argon2"
)

func DeriveSessionID(code []byte) string {
	raw := argon2.IDKey(
		code,
		[]byte(protocol.SessionIDArgonSalt),
		protocol.SessionIDArgonTime,
		protocol.SessionIDArgonMemory,
		protocol.SessionIDArgonThreads,
		protocol.SessionIDLen,
	)
	return hex.EncodeToString(raw)
}
