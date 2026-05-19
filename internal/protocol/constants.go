package protocol

const (
	SessionIDHMACKey    = "lw-session-id"
	EpochKeyInfoPrefix  = "lw-epoch-"
	SPAKE2AssociatedData = "lockwire-v1"

	KeyLen       = 32
	SessionIDLen = 16
	NonceLen     = 12
	ViewerIDLen  = 6
	GCMTagLen    = 16

	CodeWordCount = 6

	EpochDurationSec    = 60
	EpochGracePeriodSec = 5
	ViewerIDCharset     = "abcdefghijklmnopqrstuvwxyz0123456789"

	// Wire message type bytes (relay-protocol spec § Message Framing).
	MsgTypeSPAKE2    byte = 0x01 // Viewer → Relay → Sharer
	MsgTypeStream    byte = 0x02 // Sharer → Relay → all Viewers (broadcast)
	MsgTypeUnicast   byte = 0x03 // Sharer → Relay → one Viewer
	MsgTypeHeartbeat byte = 0x04 // Either → Relay (ping)
	MsgTypePong      byte = 0x05 // Relay → either (pong)
	MsgTypeControl   byte = 0x06 // Relay → Viewer (session control)

	// Control frame sub-types (payload byte after MsgTypeControl).
	CtrlRegistrationAck  byte = 0x01
	CtrlJoinAck          byte = 0x02
	CtrlSessionNotFound  byte = 0x03
	CtrlSessionEnded     byte = 0x04
	CtrlSessionFull      byte = 0x05
	CtrlSessionIDConflict byte = 0x06

	// Relay limits.
	DefaultMaxViewers       = 20
	ViewerBufferLimitBytes  = 512 * 1024 // 512 KB outbound buffer before disconnect
	SharerTimeoutSec        = 10
	ViewerTimeoutSec        = 30
	HeartbeatIntervalSec    = 5
)
