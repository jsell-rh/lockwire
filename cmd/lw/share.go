package main

import (
	"context"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jsell-rh/lockwire/internal/code"
	"github.com/jsell-rh/lockwire/internal/ipc"
	lwpty "github.com/jsell-rh/lockwire/internal/pty"
	"github.com/jsell-rh/lockwire/internal/session"
	"github.com/jsell-rh/lockwire/internal/sharer"
	"github.com/spf13/cobra"
	"golang.org/x/sys/unix"
)

func runShare(cmd *cobra.Command, relayURL string, insecure bool) error {
	if err := checkExistingSession(); err != nil {
		return err
	}

	if err := writePIDFile(); err != nil {
		return fmt.Errorf("writing PID file: %w", err)
	}
	defer removePIDFile()

	pairingCode, err := code.Generate()
	if err != nil {
		return fmt.Errorf("generating code: %w", err)
	}

	sess, err := session.NewSession([]byte(pairingCode))
	if err != nil {
		return fmt.Errorf("creating session: %w", err)
	}
	defer sess.Close()

	sessionID := sess.SessionID()

	shareURL := relayURL + "/api/share/" + sessionID

	connectCtx, connectCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer connectCancel()

	relay, err := dialRelay(connectCtx, shareURL, insecure)
	if err != nil {
		return fmt.Errorf("could not reach relay at %s — check your connection", relayURL)
	}
	defer relay.Close()

	watchURL := buildWatchURL(relayURL, pairingCode)
	fmt.Fprintf(cmd.OutOrStdout(), "code: %s\nlink: %s\n", pairingCode, watchURL)

	shell := os.Getenv("SHELL")
	if shell == "" {
		shell = "/bin/sh"
	}

	stdinFd := int(os.Stdin.Fd())

	outerCols, outerRows := uint16(80), uint16(24)
	if ws, err := unix.IoctlGetWinsize(stdinFd, unix.TIOCGWINSZ); err == nil {
		outerCols = ws.Col
		outerRows = ws.Row
	}

	ptyCols, ptyRows := outerCols, outerRows-1
	if outerRows < 3 {
		ptyRows = outerRows
	}

	oldTermios, err := setRawMode(stdinFd)
	if err != nil {
		return fmt.Errorf("setting raw mode: %w", err)
	}
	defer restoreTerminal(stdinFd, oldTermios)

	probe := newSharerProbe(os.Stdout, outerCols, outerRows, pairingCode)
	bar := probe.bar
	bar.SetScrollRegion()
	bar.Draw()
	defer func() {
		bar.Close()
		resetScrollRegion(os.Stdout)
		clearLine(os.Stdout, outerRows)
	}()

	term, err := lwpty.Start([]string{shell}, lwpty.Size{Cols: ptyCols, Rows: ptyRows}, nil)
	if err != nil {
		return fmt.Errorf("starting terminal: %w", err)
	}
	defer term.Close()

	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := os.Stdin.Read(buf)
			if n > 0 {
				term.Write(buf[:n])
			}
			if err != nil {
				return
			}
		}
	}()

	tee := io.TeeReader(term, &barRedrawWriter{w: os.Stdout, bar: bar})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sh := sharer.New(sess, relay, []byte(pairingCode), probe)

	sockPath := ipc.SocketPath(os.Getpid())
	adapter := &ipcSessionAdapter{sess: sess, revoke: sh.Revoke}
	ipcSrv, err := ipc.NewServer(sockPath, adapter, nil)
	if err != nil {
		return fmt.Errorf("starting control socket: %w", err)
	}
	defer ipcSrv.Close()
	go ipcSrv.Serve()

	_ = sh.SetTermSize(ctx, ptyCols, ptyRows)

	sigwinch := make(chan os.Signal, 1)
	signal.Notify(sigwinch, syscall.SIGWINCH)
	go func() {
		for range sigwinch {
			ws, err := unix.IoctlGetWinsize(stdinFd, unix.TIOCGWINSZ)
			if err != nil {
				continue
			}
			newCols, newRows := ws.Col, ws.Row
			newPtyRows := newRows - 1
			if newRows < 3 {
				newPtyRows = newRows
			}
			term.Resize(newCols, newPtyRows)
			sh.SetTermSize(ctx, newCols, newPtyRows)
			bar.Resize(newCols, newRows)
		}
	}()

	sigterm := make(chan os.Signal, 1)
	signal.Notify(sigterm, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigterm
		cancel()
	}()

	return sh.Run(ctx, tee)
}

func buildWatchURL(relayURL, pairingCode string) string {
	u, err := url.Parse(relayURL)
	if err != nil {
		return relayURL + "/join#" + pairingCode
	}
	scheme := "https"
	if u.Scheme == "ws" {
		scheme = "http"
	}
	return scheme + "://" + u.Host + u.Path + "/join#" + pairingCode
}

func setRawMode(fd int) (*unix.Termios, error) {
	termios, err := unix.IoctlGetTermios(fd, unix.TCGETS)
	if err != nil {
		return nil, fmt.Errorf("getting terminal attributes: %w", err)
	}
	old := *termios

	termios.Iflag &^= unix.IGNBRK | unix.BRKINT | unix.PARMRK | unix.ISTRIP | unix.INLCR | unix.IGNCR | unix.ICRNL | unix.IXON
	termios.Oflag &^= unix.OPOST
	termios.Lflag &^= unix.ECHO | unix.ECHONL | unix.ICANON | unix.ISIG | unix.IEXTEN
	termios.Cflag &^= unix.CSIZE | unix.PARENB
	termios.Cflag |= unix.CS8
	termios.Cc[unix.VMIN] = 1
	termios.Cc[unix.VTIME] = 0

	if err := unix.IoctlSetTermios(fd, unix.TCSETS, termios); err != nil {
		return nil, fmt.Errorf("setting raw mode: %w", err)
	}
	return &old, nil
}

func restoreTerminal(fd int, state *unix.Termios) {
	unix.IoctlSetTermios(fd, unix.TCSETS, state)
}

