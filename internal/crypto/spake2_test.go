package crypto

import (
	"bytes"
	"testing"
)

func TestSPAKE2RoundTrip(t *testing.T) {
	code := []byte("abandon abandon abandon abandon abandon about")

	sharer, err := NewSPAKE2Sharer(code)
	if err != nil {
		t.Fatalf("NewSPAKE2Sharer: %v", err)
	}
	viewer, err := NewSPAKE2Viewer(code)
	if err != nil {
		t.Fatalf("NewSPAKE2Viewer: %v", err)
	}

	msg1, err := sharer.Start()
	if err != nil {
		t.Fatalf("sharer.Start: %v", err)
	}

	msg2, err := viewer.Exchange(msg1)
	if err != nil {
		t.Fatalf("viewer.Exchange: %v", err)
	}

	confirm1, err := sharer.Finish(msg2)
	if err != nil {
		t.Fatalf("sharer.Finish: %v", err)
	}

	confirm2, err := viewer.Confirm(confirm1)
	if err != nil {
		t.Fatalf("viewer.Confirm: %v", err)
	}

	if err := sharer.Verify(confirm2); err != nil {
		t.Fatalf("sharer.Verify: %v", err)
	}

	sharerKey, err := sharer.SessionKey()
	if err != nil {
		t.Fatalf("sharer.SessionKey: %v", err)
	}
	viewerKey, err := viewer.SessionKey()
	if err != nil {
		t.Fatalf("viewer.SessionKey: %v", err)
	}

	if !bytes.Equal(sharerKey, viewerKey) {
		t.Error("sharer and viewer derived different session keys")
	}
	if len(sharerKey) == 0 {
		t.Error("session key is empty")
	}
}

func TestSPAKE2WrongCodeRejected(t *testing.T) {
	sharer, _ := NewSPAKE2Sharer([]byte("correct code"))
	viewer, _ := NewSPAKE2Viewer([]byte("wrong code"))

	msg1, err := sharer.Start()
	if err != nil {
		t.Fatalf("sharer.Start: %v", err)
	}

	msg2, err := viewer.Exchange(msg1)
	if err != nil {
		t.Fatalf("viewer.Exchange: %v", err)
	}

	confirm1, err := sharer.Finish(msg2)
	if err != nil {
		t.Fatalf("sharer.Finish: %v", err)
	}

	_, err = viewer.Confirm(confirm1)
	if err == nil {
		sharerKey, _ := sharer.SessionKey()
		viewerKey, _ := viewer.SessionKey()
		if bytes.Equal(sharerKey, viewerKey) {
			t.Error("wrong code produced matching keys — handshake should have failed")
		}
		return
	}
}

func TestSPAKE2DifferentSessionsProduceDifferentKeys(t *testing.T) {
	code := []byte("same code for both sessions")

	key1 := completeSPAKE2(t, code)
	key2 := completeSPAKE2(t, code)

	if bytes.Equal(key1, key2) {
		t.Error("two independent sessions produced the same key")
	}
}

func TestSPAKE2SharerCleanup(t *testing.T) {
	code := []byte("cleanup test")
	sharer, err := NewSPAKE2Sharer(code)
	if err != nil {
		t.Fatalf("NewSPAKE2Sharer: %v", err)
	}

	msg1, err := sharer.Start()
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	viewer, err := NewSPAKE2Viewer(code)
	if err != nil {
		t.Fatalf("NewSPAKE2Viewer: %v", err)
	}
	msg2, err := viewer.Exchange(msg1)
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	confirm1, err := sharer.Finish(msg2)
	if err != nil {
		t.Fatalf("Finish: %v", err)
	}
	confirm2, err := viewer.Confirm(confirm1)
	if err != nil {
		t.Fatalf("Confirm: %v", err)
	}
	if err := sharer.Verify(confirm2); err != nil {
		t.Fatalf("Verify: %v", err)
	}

	key, err := sharer.SessionKey()
	if err != nil {
		t.Fatalf("SessionKey: %v", err)
	}
	keyCopy := make([]byte, len(key))
	copy(keyCopy, key)

	sharer.Destroy()

	// After Destroy, the internal key bytes should be zeroed
	allZero := true
	for _, b := range key {
		if b != 0 {
			allZero = false
			break
		}
	}
	if !allZero {
		t.Error("session key was not zeroed after Destroy")
	}
}

func completeSPAKE2(t *testing.T, code []byte) []byte {
	t.Helper()
	sharer, err := NewSPAKE2Sharer(code)
	if err != nil {
		t.Fatalf("NewSPAKE2Sharer: %v", err)
	}
	viewer, err := NewSPAKE2Viewer(code)
	if err != nil {
		t.Fatalf("NewSPAKE2Viewer: %v", err)
	}

	msg1, err := sharer.Start()
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	msg2, err := viewer.Exchange(msg1)
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	confirm1, err := sharer.Finish(msg2)
	if err != nil {
		t.Fatalf("Finish: %v", err)
	}
	confirm2, err := viewer.Confirm(confirm1)
	if err != nil {
		t.Fatalf("Confirm: %v", err)
	}
	if err := sharer.Verify(confirm2); err != nil {
		t.Fatalf("Verify: %v", err)
	}

	key, err := sharer.SessionKey()
	if err != nil {
		t.Fatalf("SessionKey: %v", err)
	}
	out := make([]byte, len(key))
	copy(out, key)
	return out
}
