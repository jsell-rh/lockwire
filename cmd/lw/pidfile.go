package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

func pidFilePath() string {
	tmp := os.TempDir()
	return filepath.Join(tmp, "lw.pid")
}

func checkExistingSession() error {
	data, err := os.ReadFile(pidFilePath())
	if err != nil {
		return nil
	}

	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		os.Remove(pidFilePath())
		return nil
	}

	proc, err := os.FindProcess(pid)
	if err != nil {
		os.Remove(pidFilePath())
		return nil
	}

	if err := proc.Signal(syscall.Signal(0)); err != nil {
		os.Remove(pidFilePath())
		return nil
	}

	return fmt.Errorf("a session is already active (pid %d). Run 'lw list' to see viewers", pid)
}

func writePIDFile() error {
	return os.WriteFile(pidFilePath(), []byte(strconv.Itoa(os.Getpid())), 0600)
}

func removePIDFile() {
	os.Remove(pidFilePath())
}
