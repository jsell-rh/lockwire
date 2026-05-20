package main

import (
	"fmt"
	"io"
	"sync/atomic"
)

type statusBarSharerProbe struct {
	bar          *statusBar
	viewerCount  atomic.Int32
}

func newSharerProbe(out io.Writer, cols, totalRows uint16, code string) *statusBarSharerProbe {
	p := &statusBarSharerProbe{}
	p.bar = newStatusBar(statusBarConfig{
		out:       out,
		cols:      cols,
		totalRows: totalRows,
		color:     colorCyberCyan,
		content: func() string {
			n := int(p.viewerCount.Load())
			noun := "viewers"
			if n == 1 {
				noun = "viewer"
			}
			return fmt.Sprintf("lw | code: %s | %d %s | lw stop to end", bold(code), n, noun)
		},
	})
	return p
}

func (p *statusBarSharerProbe) SessionCreated(sessionID, code string)    {}
func (p *statusBarSharerProbe) RelayConnected(url string)                {}
func (p *statusBarSharerProbe) FrameStreamed(epoch uint64, size int)      {}
func (p *statusBarSharerProbe) SessionTerminated(reason string)          {}
func (p *statusBarSharerProbe) HeartbeatSent()                           {}
func (p *statusBarSharerProbe) TerminalSizeBroadcast(uint16, uint16)     {}

func (p *statusBarSharerProbe) ViewerJoined(viewerID, clientType string) {
	p.viewerCount.Add(1)
	p.bar.ShowEvent(fmt.Sprintf("viewer joined: %s (%s)", viewerID, clientType))
}

func (p *statusBarSharerProbe) ViewerLeft(viewerID string) {
	p.viewerCount.Add(-1)
	p.bar.ShowEvent(fmt.Sprintf("viewer left: %s", viewerID))
}

func (p *statusBarSharerProbe) ViewerRevoked(viewerID string) {
	p.viewerCount.Add(-1)
	p.bar.ShowEvent(fmt.Sprintf("revoked: %s", viewerID))
}

func (p *statusBarSharerProbe) HandshakeFailed(viewerID string, err error) {
	p.bar.ShowEvent(fmt.Sprintf("handshake failed: %s", viewerID))
}
