package pty

import (
	"fmt"
	"os"
	"os/exec"
	"sync"

	"github.com/creack/pty"
)

type Size struct {
	Cols uint16
	Rows uint16
}

type Terminal struct {
	cmd     *exec.Cmd
	ptmx    *os.File
	probe   Probe
	size    Size
	mu      sync.Mutex
	done    chan struct{}
	exitErr error
}

func Start(argv []string, size Size, probe Probe) (*Terminal, error) {
	if len(argv) == 0 {
		return nil, fmt.Errorf("starting terminal: argv must not be empty")
	}
	if probe == nil {
		probe = noopProbe{}
	}

	cmd := exec.Command(argv[0], argv[1:]...)
	ptmx, err := pty.StartWithSize(cmd, &pty.Winsize{
		Cols: size.Cols,
		Rows: size.Rows,
	})
	if err != nil {
		return nil, fmt.Errorf("starting pty: %w", err)
	}

	t := &Terminal{
		cmd:   cmd,
		ptmx:  ptmx,
		probe: probe,
		size:  size,
		done:  make(chan struct{}),
	}

	probe.ShellStarted(cmd.Process.Pid, size.Cols, size.Rows)

	go t.waitForExit()

	return t, nil
}

func (t *Terminal) Read(b []byte) (int, error) {
	n, err := t.ptmx.Read(b)
	if n > 0 {
		t.probe.OutputRead(n)
	}
	return n, err
}

func (t *Terminal) Write(b []byte) (int, error) {
	return t.ptmx.Write(b)
}

func (t *Terminal) Resize(cols, rows uint16) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if err := pty.Setsize(t.ptmx, &pty.Winsize{Cols: cols, Rows: rows}); err != nil {
		return fmt.Errorf("resizing pty: %w", err)
	}
	t.size = Size{Cols: cols, Rows: rows}
	t.probe.Resized(cols, rows)
	return nil
}

func (t *Terminal) Size() Size {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.size
}

func (t *Terminal) Pid() int {
	if t.cmd.Process == nil {
		return 0
	}
	return t.cmd.Process.Pid
}

func (t *Terminal) Wait() error {
	<-t.done
	return t.exitErr
}

func (t *Terminal) Close() {
	t.ptmx.Close()
	<-t.done
}

func (t *Terminal) waitForExit() {
	err := t.cmd.Wait()
	t.exitErr = err
	t.probe.ShellExited(err)
	close(t.done)
}
