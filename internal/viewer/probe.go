package viewer

type Probe interface {
	Connecting()
	HandshakeCompleted(viewerID string)
	FrameDecrypted(epoch uint64, size int)
	SessionEnded(reason string)
	HandshakeFailed(err error)
	HeartbeatSent()
}

type noopProbe struct{}

func (noopProbe) Connecting()                    {}
func (noopProbe) HandshakeCompleted(string)      {}
func (noopProbe) FrameDecrypted(uint64, int)     {}
func (noopProbe) SessionEnded(string)            {}
func (noopProbe) HandshakeFailed(error)          {}
func (noopProbe) HeartbeatSent()                 {}
