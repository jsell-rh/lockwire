package relay

type Probe interface {
	AcceptError(handler string, err error)
}

type noopRelayProbe struct{}

func (noopRelayProbe) AcceptError(string, error) {}
