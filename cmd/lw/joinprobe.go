package main

import (
	"fmt"
	"io"
)

type stdoutViewerProbe struct {
	out io.Writer
}

func (p *stdoutViewerProbe) Connecting() {}

func (p *stdoutViewerProbe) HandshakeCompleted(viewerID string) {
	fmt.Fprint(p.out, "\r\033[K")
}

func (p *stdoutViewerProbe) FrameDecrypted(uint64, int) {}

func (p *stdoutViewerProbe) StreamKeyRotated() {}

func (p *stdoutViewerProbe) AccessRevoked() {}

func (p *stdoutViewerProbe) SessionEnded(string) {}

func (p *stdoutViewerProbe) HandshakeFailed(error) {}

func (p *stdoutViewerProbe) HeartbeatSent() {}

func (p *stdoutViewerProbe) TerminalResized(uint16, uint16) {}
