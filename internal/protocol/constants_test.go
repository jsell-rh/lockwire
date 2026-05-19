package protocol

import "testing"

func TestConstantsMatchSpec(t *testing.T) {
	if SessionIDHMACKey != "lw-session-id" {
		t.Errorf("SessionIDHMACKey = %q, want %q", SessionIDHMACKey, "lw-session-id")
	}
	if EpochKeyInfoPrefix != "lw-epoch-" {
		t.Errorf("EpochKeyInfoPrefix = %q, want %q", EpochKeyInfoPrefix, "lw-epoch-")
	}
	if SPAKE2AssociatedData != "lockwire-v1" {
		t.Errorf("SPAKE2AssociatedData = %q, want %q", SPAKE2AssociatedData, "lockwire-v1")
	}
	if KeyLen != 32 {
		t.Errorf("KeyLen = %d, want 32", KeyLen)
	}
	if SessionIDLen != 16 {
		t.Errorf("SessionIDLen = %d, want 16", SessionIDLen)
	}
	if NonceLen != 12 {
		t.Errorf("NonceLen = %d, want 12", NonceLen)
	}
	if ViewerIDLen != 6 {
		t.Errorf("ViewerIDLen = %d, want 6", ViewerIDLen)
	}
	if GCMTagLen != 16 {
		t.Errorf("GCMTagLen = %d, want 16 (128-bit)", GCMTagLen)
	}
}
