package main

import (
	"errors"
	"fmt"
	"net/url"

	"github.com/spf13/cobra"
)

const defaultRelayURL = "wss://relay.lockwire.io"

func newRootCmd(ver string) *cobra.Command {
	root := &cobra.Command{
		Use:           "lw",
		Short:         "E2E-encrypted terminal sharing",
		Version:       ver,
		SilenceErrors: true,
	}

	root.SetVersionTemplate("lw {{.Version}}\n")
	root.AddCommand(newShareCmd())
	root.AddCommand(newJoinCmd())
	root.AddCommand(newListCmd())

	return root
}

func newShareCmd() *cobra.Command {
	var relayURL string
	var insecure bool

	cmd := &cobra.Command{
		Use:   "share",
		Short: "Start a terminal sharing session",
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

			return runShare(cmd, relayURL, insecure)
		},
	}

	cmd.Flags().StringVar(&relayURL, "relay", defaultRelayURL, "relay WebSocket URL")
	cmd.Flags().BoolVar(&insecure, "relay-insecure", false, "allow non-TLS relay (development only)")

	return cmd
}

func validateRelayURL(raw string) error {
	if raw == "" {
		return errors.New("relay URL must not be empty")
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return fmt.Errorf("relay URL must use wss://")
	}
	if u.Scheme != "wss" {
		return errors.New("relay URL must use wss:// (TLS required)")
	}
	return nil
}

func validateRelayURLInsecure(raw string) error {
	if raw == "" {
		return errors.New("relay URL must not be empty")
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" {
		return fmt.Errorf("relay URL must use ws:// or wss://")
	}
	if u.Scheme != "wss" && u.Scheme != "ws" {
		return fmt.Errorf("relay URL must use ws:// or wss://")
	}
	return nil
}
