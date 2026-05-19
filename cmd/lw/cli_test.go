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
