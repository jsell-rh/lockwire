package relay

type Probe interface {
	AcceptError(handler string, err error)
	RateLimited(ip string, activity string)
	BanTriggered(ip string, activity string, duration string)
	ConnectionAccepted(handler string, clientIP string)
}

type noopRelayProbe struct{}

func (noopRelayProbe) AcceptError(string, error)          {}
func (noopRelayProbe) RateLimited(string, string)         {}
func (noopRelayProbe) BanTriggered(string, string, string) {}
func (noopRelayProbe) ConnectionAccepted(string, string)  {}
