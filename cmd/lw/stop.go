package main

import (
	"fmt"

	"github.com/jsell-rh/lockwire/internal/ipc"
	"github.com/spf13/cobra"
)

func newStopCmd() *cobra.Command {
	return &cobra.Command{
		Use:          "stop",
		Short:        "Stop the active sharing session",
		Args:         cobra.NoArgs,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runStop(cmd)
		},
	}
}

func runStop(cmd *cobra.Command) error {
	sockPath, err := resolveSocketPath()
	if err != nil {
		return err
	}

	if err := ipc.ClientStop(sockPath); err != nil {
		return fmt.Errorf("stopping session: %w", err)
	}

	fmt.Fprintln(cmd.OutOrStdout(), "session stopped")
	return nil
}
