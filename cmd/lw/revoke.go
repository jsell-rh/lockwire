package main

import (
	"fmt"

	"github.com/jsell-rh/lockwire/internal/ipc"
	"github.com/spf13/cobra"
)

func newRevokeCmd() *cobra.Command {
	return &cobra.Command{
		Use:          "revoke <viewer-id>",
		Short:        "Revoke a viewer's access to the active session",
		Args:         cobra.ExactArgs(1),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runRevoke(cmd, args[0])
		},
	}
}

func runRevoke(cmd *cobra.Command, viewerID string) error {
	sockPath, err := resolveSocketPath()
	if err != nil {
		return err
	}

	if err := ipc.ClientRevoke(sockPath, viewerID); err != nil {
		if err.Error() == "viewer not found" {
			return fmt.Errorf("viewer not found")
		}
		return fmt.Errorf("no active session")
	}

	fmt.Fprintf(cmd.OutOrStdout(), "revoked %s\n", viewerID)
	return nil
}
