package pty

type Probe interface {
	ShellStarted(pid int, cols, rows uint16)
	OutputRead(n int)
	Resized(cols, rows uint16)
	ShellExited(err error)
}

type noopProbe struct{}

func (noopProbe) ShellStarted(int, uint16, uint16) {}
func (noopProbe) OutputRead(int)                    {}
func (noopProbe) Resized(uint16, uint16)            {}
func (noopProbe) ShellExited(error)                 {}
