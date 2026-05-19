package main

import (
	"fmt"
	"io"
)

type stdoutSharerProbe struct {
	out io.Writer
}

func (p *stdoutSharerProbe) SessionCreated(sessionID, code string)    {}
func (p *stdoutSharerProbe) RelayConnected(url string)                {}
func (p *stdoutSharerProbe) FrameStreamed(epoch uint64, size int)      {}
func (p *stdoutSharerProbe) SessionTerminated(reason string)          {}
func (p *stdoutSharerProbe) HeartbeatSent()                           {}

func (p *stdoutSharerProbe) ViewerJoined(viewerID, clientType string) {
	fmt.Fprintf(p.out, "viewer joined: %s (%s)\n", viewerID, clientType)
}

func (p *stdoutSharerProbe) ViewerLeft(viewerID string) {
	fmt.Fprintf(p.out, "viewer left: %s\n", viewerID)
}

func (p *stdoutSharerProbe) HandshakeFailed(viewerID string, err error) {
	fmt.Fprintf(p.out, "handshake failed for viewer %s\n", viewerID)
}

func (p *stdoutSharerProbe) TerminalSizeBroadcast(uint16, uint16) {}
