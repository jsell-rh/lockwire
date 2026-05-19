package sharer

type Probe interface {
	SessionCreated(sessionID string, code string)
	RelayConnected(url string)
	ViewerJoined(viewerID string, clientType string)
	ViewerLeft(viewerID string)
	FrameStreamed(epoch uint64, size int)
	SessionTerminated(reason string)
	HandshakeFailed(viewerID string, err error)
	HeartbeatSent()
}

type noopProbe struct{}

func (noopProbe) SessionCreated(string, string)      {}
func (noopProbe) RelayConnected(string)               {}
func (noopProbe) ViewerJoined(string, string)          {}
func (noopProbe) ViewerLeft(string)                    {}
func (noopProbe) FrameStreamed(uint64, int)             {}
func (noopProbe) SessionTerminated(string)             {}
func (noopProbe) HandshakeFailed(string, error)        {}
func (noopProbe) HeartbeatSent()                       {}
