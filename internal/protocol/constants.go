package protocol

const (
	SessionIDHMACKey = "lw-session-id"
	EpochKeyInfoPrefix = "lw-epoch-"
	SPAKE2AssociatedData = "lockwire-v1"

	KeyLen       = 32
	SessionIDLen = 16
	NonceLen     = 12
	ViewerIDLen  = 6
	GCMTagLen    = 16

	CodeWordCount = 6

	EpochDurationSec       = 60
	EpochGracePeriodSec    = 5
	ViewerIDCharset        = "abcdefghijklmnopqrstuvwxyz0123456789"
)
