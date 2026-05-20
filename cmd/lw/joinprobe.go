package main

import "fmt"

type viewerStatusBarProbe struct {
	bar *statusBar
}

func (p *viewerStatusBarProbe) Connecting() {}

func (p *viewerStatusBarProbe) HandshakeCompleted(viewerID string) {
	fmt.Fprint(p.bar.out, "\r\033[K")
}

func (p *viewerStatusBarProbe) FrameDecrypted(uint64, int) {}

func (p *viewerStatusBarProbe) StreamKeyRotated() {}

func (p *viewerStatusBarProbe) AccessRevoked() {}

func (p *viewerStatusBarProbe) SessionEnded(string) {}

func (p *viewerStatusBarProbe) HandshakeFailed(error) {}

func (p *viewerStatusBarProbe) HeartbeatSent() {}

func (p *viewerStatusBarProbe) TerminalResized(uint16, uint16) {}
