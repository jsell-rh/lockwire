package main

import (
	"fmt"
	"io"
	"time"
)

type logRelayProbe struct {
	out io.Writer
}

func (p *logRelayProbe) AcceptError(handler string, err error) {
	fmt.Fprintf(p.out, "%s [relay] accept error on %s: %v\n",
		time.Now().UTC().Format(time.RFC3339), handler, err)
}

func (p *logRelayProbe) RateLimited(ip string, activity string) {
	fmt.Fprintf(p.out, "%s [relay] rate limited ip=%s activity=%s\n",
		time.Now().UTC().Format(time.RFC3339), ip, activity)
}

func (p *logRelayProbe) BanTriggered(ip string, activity string, duration string) {
	fmt.Fprintf(p.out, "%s [relay] ban triggered ip=%s activity=%s duration=%s\n",
		time.Now().UTC().Format(time.RFC3339), ip, activity, duration)
}
