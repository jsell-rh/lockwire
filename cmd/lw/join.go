package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jsell-rh/lockwire/internal/code"
	"github.com/jsell-rh/lockwire/internal/crypto"
	"github.com/jsell-rh/lockwire/internal/viewer"
	"github.com/spf13/cobra"
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

	probe := &stdoutViewerProbe{out: cmd.ErrOrStderr()}
	v := viewer.New(relay, []byte(normalized), os.Stdout, probe)

	err = v.Run(ctx)

	switch {
	case err == nil:
		return nil
	case errors.Is(err, viewer.ErrSessionNotFound):
		fmt.Fprintln(cmd.ErrOrStderr(), "\rerror: session not found")
		return err
	case errors.Is(err, viewer.ErrHandshakeTimeout):
		fmt.Fprintln(cmd.ErrOrStderr(), "\rerror: handshake timed out")
		return err
	case errors.Is(err, viewer.ErrSessionEnded):
		fmt.Fprintln(cmd.OutOrStdout(), "\nsession ended by sharer")
		return nil
	case errors.Is(err, viewer.ErrConnectionLost):
		fmt.Fprintln(cmd.ErrOrStderr(), "\nsession lost (connection dropped)")
		return err
	default:
		return err
	}
}
