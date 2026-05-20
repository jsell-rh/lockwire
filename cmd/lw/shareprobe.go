package main

import "fmt"

type statusBarSharerProbe struct {
	bar *statusBar
}

func (p *statusBarSharerProbe) SessionCreated(sessionID, code string)    {}
func (p *statusBarSharerProbe) RelayConnected(url string)                {}
func (p *statusBarSharerProbe) FrameStreamed(epoch uint64, size int)      {}
func (p *statusBarSharerProbe) SessionTerminated(reason string)          {}
func (p *statusBarSharerProbe) HeartbeatSent()                           {}
func (p *statusBarSharerProbe) TerminalSizeBroadcast(uint16, uint16)     {}

func (p *statusBarSharerProbe) ViewerJoined(viewerID, clientType string) {
	p.bar.IncrementViewers()
	p.bar.ShowEvent(fmt.Sprintf("viewer joined: %s (%s)", viewerID, clientType))
}

func (p *statusBarSharerProbe) ViewerLeft(viewerID string) {
	p.bar.DecrementViewers()
	p.bar.ShowEvent(fmt.Sprintf("viewer left: %s", viewerID))
}

func (p *statusBarSharerProbe) ViewerRevoked(viewerID string) {
	p.bar.DecrementViewers()
	p.bar.ShowEvent(fmt.Sprintf("revoked: %s", viewerID))
}

func (p *statusBarSharerProbe) HandshakeFailed(viewerID string, err error) {
	p.bar.ShowEvent(fmt.Sprintf("handshake failed: %s", viewerID))
}
