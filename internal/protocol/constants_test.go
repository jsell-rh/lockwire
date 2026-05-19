package protocol

import "testing"

func TestConstantsMatchSpec(t *testing.T) {
	if SessionIDArgonSalt != "lockwire-session-id-v1" {
		t.Errorf("SessionIDArgonSalt = %q, want %q", SessionIDArgonSalt, "lockwire-session-id-v1")
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

func TestMessageTypeConstants(t *testing.T) {
	cases := []struct {
		name string
		got  byte
		want byte
	}{
		{"MsgTypeSPAKE2", MsgTypeSPAKE2, 0x01},
		{"MsgTypeStream", MsgTypeStream, 0x02},
		{"MsgTypeUnicast", MsgTypeUnicast, 0x03},
		{"MsgTypeHeartbeat", MsgTypeHeartbeat, 0x04},
		{"MsgTypePong", MsgTypePong, 0x05},
		{"MsgTypeControl", MsgTypeControl, 0x06},
	}
	for _, tc := range cases {
		if tc.got != tc.want {
			t.Errorf("%s = 0x%02x, want 0x%02x", tc.name, tc.got, tc.want)
		}
	}
}

func TestRelayLimitConstants(t *testing.T) {
	if DefaultMaxViewers != 20 {
		t.Errorf("DefaultMaxViewers = %d, want 20", DefaultMaxViewers)
	}
	if ViewerBufferLimitBytes != 512*1024 {
		t.Errorf("ViewerBufferLimitBytes = %d, want %d", ViewerBufferLimitBytes, 512*1024)
	}
	if SharerTimeoutSec != 10 {
		t.Errorf("SharerTimeoutSec = %d, want 10", SharerTimeoutSec)
	}
	if ViewerTimeoutSec != 30 {
		t.Errorf("ViewerTimeoutSec = %d, want 30", ViewerTimeoutSec)
	}
}
