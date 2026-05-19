package crypto

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"

	"github.com/jsell-rh/lockwire/internal/protocol"
)

func DeriveSessionID(k []byte) string {
	mac := hmac.New(sha256.New, k)
	mac.Write([]byte(protocol.SessionIDHMACKey))
	full := mac.Sum(nil)
	return hex.EncodeToString(full[:protocol.SessionIDLen])
}
