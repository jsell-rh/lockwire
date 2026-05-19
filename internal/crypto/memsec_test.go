package crypto

import "testing"

func TestZeroBytesOverwritesSlice(t *testing.T) {
	buf := []byte{0xff, 0xfe, 0xfd, 0xfc, 0xfb}
	ZeroBytes(buf)
	for i, b := range buf {
		if b != 0 {
			t.Errorf("buf[%d] = 0x%02x, want 0x00", i, b)
		}
	}
}

func TestZeroBytesNilIsNoOp(t *testing.T) {
	ZeroBytes(nil)
}

func TestZeroBytesEmptyIsNoOp(t *testing.T) {
	ZeroBytes([]byte{})
}

func TestNewSecureBufferReturnsZeroedSlice(t *testing.T) {
	buf, err := NewSecureBuffer(32)
	if err != nil {
		t.Fatalf("NewSecureBuffer(32): %v", err)
	}
	defer ZeroBytes(buf)

	if len(buf) != 32 {
		t.Errorf("len = %d, want 32", len(buf))
	}
	for i, b := range buf {
		if b != 0 {
			t.Errorf("buf[%d] = 0x%02x, want 0x00", i, b)
		}
	}
}

func TestNewSecureBufferZeroSizeErrors(t *testing.T) {
	_, err := NewSecureBuffer(0)
	if err == nil {
		t.Error("expected error for size 0")
	}
}
