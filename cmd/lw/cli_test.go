package main

import (
	"bytes"
	"testing"
)

func TestVersionFlag(t *testing.T) {
	var out bytes.Buffer
	cmd := newRootCmd("v1.2.3")
	cmd.SetOut(&out)
	cmd.SetArgs([]string{"--version"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}

	got := out.String()
	want := "lw v1.2.3\n"
	if got != want {
		t.Errorf("version output = %q, want %q", got, want)
	}
}

func TestShareRelayURLValidation(t *testing.T) {
	tests := []struct {
		name    string
		url     string
		wantErr string
	}{
		{
			name:    "ws scheme rejected",
			url:     "ws://localhost:8080",
			wantErr: "relay URL must use wss:// (TLS required)",
		},
		{
			name:    "http scheme rejected",
			url:     "http://localhost:8080",
			wantErr: "relay URL must use wss:// (TLS required)",
		},
		{
			name:    "no scheme rejected",
			url:     "localhost:8080",
			wantErr: "relay URL must use wss://",
		},
		{
			name:    "empty rejected",
			url:     "",
			wantErr: "relay URL must not be empty",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateRelayURL(tt.url)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if got := err.Error(); got != tt.wantErr {
				t.Errorf("error = %q, want %q", got, tt.wantErr)
			}
		})
	}
}

func TestShareRelayURLValidAccepted(t *testing.T) {
	tests := []struct {
		name string
		url  string
	}{
		{name: "standard wss", url: "wss://relay.lockwire.io"},
		{name: "wss with path", url: "wss://host.example.com/lockwire"},
		{name: "wss with port", url: "wss://localhost:8443"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := validateRelayURL(tt.url); err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

func TestShareRelayInsecureAllowsWS(t *testing.T) {
	err := validateRelayURLInsecure("ws://localhost:8080")
	if err != nil {
		t.Errorf("insecure mode should allow ws://, got: %v", err)
	}
}

func TestBuildWatchURL(t *testing.T) {
	tests := []struct {
		relay string
		code  string
		want  string
	}{
		{
			relay: "wss://relay.lockwire.io",
			code:  "thunder-eagle-river-moon-stone-fire",
			want:  "https://relay.lockwire.io/join#thunder-eagle-river-moon-stone-fire",
		},
		{
			relay: "wss://relay.example.com/lockwire",
			code:  "test-code",
			want:  "https://relay.example.com/lockwire/join#test-code",
		},
		{
			relay: "ws://localhost:8080",
			code:  "test-code",
			want:  "http://localhost:8080/join#test-code",
		},
	}

	for _, tt := range tests {
		t.Run(tt.relay, func(t *testing.T) {
			got := buildWatchURL(tt.relay, tt.code)
			if got != tt.want {
				t.Errorf("buildWatchURL(%q, %q) = %q, want %q", tt.relay, tt.code, got, tt.want)
			}
		})
	}
}

func TestPIDFileWriteAndRemove(t *testing.T) {
	// Clean up any existing PID file from previous runs.
	removePIDFile()

	if err := checkExistingSession(); err != nil {
		t.Fatalf("unexpected error with no PID file: %v", err)
	}

	if err := writePIDFile(); err != nil {
		t.Fatalf("writePIDFile: %v", err)
	}

	// Our own PID should be detected as active.
	err := checkExistingSession()
	if err == nil {
		t.Fatal("expected error for existing session")
	}

	removePIDFile()

	if err := checkExistingSession(); err != nil {
		t.Fatalf("after removal, unexpected error: %v", err)
	}
}
