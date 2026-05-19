package main

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/jsell-rh/lockwire/internal/code"
	"github.com/jsell-rh/lockwire/internal/session"
	"github.com/jsell-rh/lockwire/internal/sharer"
	lwpty "github.com/jsell-rh/lockwire/internal/pty"
	"github.com/spf13/cobra"
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
	if !insecure {
		shareURL = strings.Replace(shareURL, "wss://", "wss://", 1)
	}

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

	term, err := lwpty.Start([]string{shell}, lwpty.Size{Cols: 80, Rows: 24}, nil)
	if err != nil {
		return fmt.Errorf("starting terminal: %w", err)
	}
	defer term.Close()

	// Forward stdin to the PTY.
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

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	probe := &stdoutSharerProbe{out: cmd.ErrOrStderr()}
	sh := sharer.New(sess, relay, []byte(pairingCode), probe)

	// Handle SIGWINCH for terminal resize.
	sigwinch := make(chan os.Signal, 1)
	signal.Notify(sigwinch, syscall.SIGWINCH)
	go func() {
		for range sigwinch {
			// In a real implementation, we'd get the actual terminal size.
			// For now, the PTY starts with the initial size.
		}
	}()

	// Handle SIGINT/SIGTERM for graceful shutdown.
	sigterm := make(chan os.Signal, 1)
	signal.Notify(sigterm, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigterm
		cancel()
	}()

	return sh.Run(ctx, term)
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
