package main

import (
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/jsell-rh/lockwire/internal/ipc"
	"github.com/spf13/cobra"
)

func newListCmd() *cobra.Command {
	return &cobra.Command{
		Use:          "list",
		Aliases:      []string{"viewers"},
		Short:        "List connected viewers for the active session",
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runList(cmd)
		},
	}
}

func runList(cmd *cobra.Command) error {
	sockPath, err := resolveSocketPath()
	if err != nil {
		return err
	}

	viewers, err := ipc.ClientList(sockPath)
	if err != nil {
		return fmt.Errorf("no active session")
	}

	if len(viewers) == 0 {
		fmt.Fprintln(cmd.OutOrStdout(), "no viewers connected")
		return nil
	}

	now := time.Now()
	for _, v := range viewers {
		fmt.Fprintf(cmd.OutOrStdout(), "%s  %-7s  joined %s\n",
			v.ID, v.ClientType, formatDuration(now.Sub(v.JoinTime)))
	}
	return nil
}

func resolveSocketPath() (string, error) {
	data, err := os.ReadFile(pidFilePath())
	if err == nil {
		pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
		if err == nil {
			path := ipc.SocketPath(pid)
			if _, err := os.Stat(path); err == nil {
				return path, nil
			}
		}
	}

	matches, _ := filepath.Glob(filepath.Join(os.TempDir(), "lw-*.sock"))
	for _, m := range matches {
		base := filepath.Base(m)
		pidStr := strings.TrimPrefix(base, "lw-")
		pidStr = strings.TrimSuffix(pidStr, ".sock")
		pid, err := strconv.Atoi(pidStr)
		if err != nil {
			continue
		}
		if isProcessAlive(pid) {
			return m, nil
		}
	}

	return "", fmt.Errorf("no active session")
}

func isProcessAlive(pid int) bool {
	proc, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	return proc.Signal(syscall.Signal(0)) == nil
}

func formatDuration(d time.Duration) string {
	if d < time.Minute {
		return fmt.Sprintf("%ds ago", int(math.Max(1, d.Seconds())))
	}
	if d < time.Hour {
		return fmt.Sprintf("%dm ago", int(d.Minutes()))
	}
	return fmt.Sprintf("%dh ago", int(d.Hours()))
}
