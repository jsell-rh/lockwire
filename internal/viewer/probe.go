package viewer

type Probe interface {
	Connecting()
	HandshakeCompleted(viewerID string)
	FrameDecrypted(epoch uint64, size int)
	StreamKeyRotated()
	AccessRevoked()
	SessionEnded(reason string)
	HandshakeFailed(err error)
	HeartbeatSent()
}

type noopProbe struct{}

func (noopProbe) Connecting()                    {}
func (noopProbe) HandshakeCompleted(string)      {}
func (noopProbe) FrameDecrypted(uint64, int)     {}
func (noopProbe) StreamKeyRotated()              {}
func (noopProbe) AccessRevoked()                 {}
func (noopProbe) SessionEnded(string)            {}
func (noopProbe) HandshakeFailed(error)          {}
func (noopProbe) HeartbeatSent()                 {}
