package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/jsell-rh/lockwire/internal/code"
	"github.com/jsell-rh/lockwire/internal/crypto"
	"github.com/jsell-rh/lockwire/internal/viewer"
	"github.com/spf13/cobra"
	"golang.org/x/sys/unix"
)

func newJoinCmd() *cobra.Command {
	var relayURL string
	var insecure bool

	cmd := &cobra.Command{
		Use:          "join <code>",
		Short:        "Join a terminal sharing session",
		Args:         cobra.ExactArgs(1),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			var err error
			if insecure {
				err = validateRelayURLInsecure(relayURL)
			} else {
				err = validateRelayURL(relayURL)
			}
			if err != nil {
				return err
			}

			return runJoin(cmd, args[0], relayURL, insecure)
		},
	}

	cmd.Flags().StringVar(&relayURL, "relay", defaultRelayURL, "relay WebSocket URL")
	cmd.Flags().BoolVar(&insecure, "relay-insecure", false, "allow non-TLS relay (development only)")

	return cmd
}

func runJoin(cmd *cobra.Command, rawCode, relayURL string, insecure bool) error {
	normalized, err := code.Normalize(rawCode)
	if err != nil {
		return fmt.Errorf("invalid code: %w", err)
	}

	sessionID := crypto.DeriveSessionID([]byte(normalized))
	watchURL := relayURL + "/api/watch/" + sessionID

	fmt.Fprint(cmd.ErrOrStderr(), "connecting…")

	connectCtx, connectCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer connectCancel()

	relay, err := dialRelay(connectCtx, watchURL, insecure)
	if err != nil {
		fmt.Fprintln(cmd.ErrOrStderr())
		return fmt.Errorf("could not reach relay at %s — check your connection", relayURL)
	}
	defer relay.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigterm := make(chan os.Signal, 1)
	signal.Notify(sigterm, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigterm
		cancel()
	}()

	stdinFd := int(os.Stdin.Fd())

	outerCols, outerRows := uint16(80), uint16(24)
	if ws, err := unix.IoctlGetWinsize(stdinFd, unix.TIOCGWINSZ); err == nil {
		outerCols = ws.Col
		outerRows = ws.Row
	}

	oldTermios, err := setRawMode(stdinFd)
	if err != nil {
		return fmt.Errorf("setting raw mode: %w", err)
	}
	defer restoreTerminal(stdinFd, oldTermios)

	var sizeSuffix atomic.Value
	sizeSuffix.Store("")

	bar := newStatusBar(statusBarConfig{
		out:       os.Stdout,
		cols:      outerCols,
		totalRows: outerRows,
		color:     colorWarningAmber,
		content: func() string {
			suffix, _ := sizeSuffix.Load().(string)
			return "lw | watching " + normalized + suffix
		},
	})
	fmt.Fprint(os.Stdout, "\033[2J\033[H")
	bar.SetScrollRegion()
	bar.Draw()
	defer func() {
		bar.Close()
		resetScrollRegion(os.Stdout)
		clearLine(os.Stdout, outerRows)
	}()

	probe := &viewerStatusBarProbe{bar: bar}
	v := viewer.New(relay, []byte(normalized), os.Stdout, probe)

	v.SetResizeHandler(func(cols, rows uint16) {
		tryResizeTerminal(stdinFd, cols, outerRows)

		ws, wsErr := unix.IoctlGetWinsize(stdinFd, unix.TIOCGWINSZ)
		if wsErr != nil {
			return
		}
		if ws.Col < cols {
			sizeSuffix.Store(fmt.Sprintf(" [sharer: %d cols]", cols))
		} else {
			sizeSuffix.Store("")
		}
		bar.Draw()
	})

	err = v.Run(ctx)

	restoreTerminal(stdinFd, oldTermios)
	resetScrollRegion(os.Stdout)
	clearLine(os.Stdout, outerRows)

	switch {
	case err == nil:
		return nil
	case errors.Is(err, viewer.ErrSessionNotFound):
		fmt.Fprintln(cmd.ErrOrStderr(), "error: session not found")
		return err
	case errors.Is(err, viewer.ErrHandshakeTimeout):
		fmt.Fprintln(cmd.ErrOrStderr(), "error: handshake timed out")
		return err
	case errors.Is(err, viewer.ErrSessionEnded):
		fmt.Fprintln(cmd.OutOrStdout(), "session ended by sharer")
		return nil
	case errors.Is(err, viewer.ErrConnectionLost):
		fmt.Fprintln(cmd.ErrOrStderr(), "session lost (connection dropped)")
		return err
	case errors.Is(err, viewer.ErrAccessRevoked):
		fmt.Fprintln(cmd.ErrOrStderr(), "access revoked")
		return err
	default:
		return err
	}
}

func tryResizeTerminal(fd int, cols, rows uint16) {
	fmt.Fprintf(os.Stdout, "\033[8;%d;%dt", rows, cols)
}

func resetScrollRegion(w io.Writer) {
	fmt.Fprint(w, "\033[r")
}

func clearLine(w io.Writer, row uint16) {
	fmt.Fprintf(w, "\033[%d;1H\033[2K", row)
}
