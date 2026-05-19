package crypto

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"regexp"
	"sync"
	"testing"

	"github.com/jsell-rh/lockwire/internal/protocol"
	"golang.org/x/crypto/hkdf"
)

// --- Stream Key ---

func TestGenerateStreamKeyLength(t *testing.T) {
	k, err := GenerateStreamKey()
	if err != nil {
		t.Fatalf("GenerateStreamKey: %v", err)
	}
	defer ZeroBytes(k)
	if len(k) != protocol.KeyLen {
		t.Errorf("len = %d, want %d", len(k), protocol.KeyLen)
	}
}

func TestGenerateStreamKeyUniqueness(t *testing.T) {
	k1, _ := GenerateStreamKey()
	k2, _ := GenerateStreamKey()
	defer ZeroBytes(k1)
	defer ZeroBytes(k2)
	if bytes.Equal(k1, k2) {
		t.Error("two generated keys are identical")
	}
}

// --- Session ID ---

func TestDeriveSessionIDKnownAnswer(t *testing.T) {
	k := make([]byte, 32)
	for i := range k {
		k[i] = byte(i)
	}
	mac := hmac.New(sha256.New, k)
	mac.Write([]byte(protocol.SessionIDHMACKey))
	full := mac.Sum(nil)
	want := hex.EncodeToString(full[:protocol.SessionIDLen])

	got := DeriveSessionID(k)
	if got != want {
		t.Errorf("DeriveSessionID = %q, want %q", got, want)
	}
}

func TestDeriveSessionIDLength(t *testing.T) {
	k := make([]byte, 32)
	sid := DeriveSessionID(k)
	if len(sid) != protocol.SessionIDLen*2 {
		t.Errorf("session ID length = %d, want %d hex chars", len(sid), protocol.SessionIDLen*2)
	}
}

func TestDeriveSessionIDDeterministic(t *testing.T) {
	k := make([]byte, 32)
	k[0] = 0x42
	s1 := DeriveSessionID(k)
	s2 := DeriveSessionID(k)
	if s1 != s2 {
		t.Errorf("same key produced different session IDs: %q vs %q", s1, s2)
	}
}

func TestDeriveSessionIDDifferentKeys(t *testing.T) {
	k1 := make([]byte, 32)
	k2 := make([]byte, 32)
	k2[0] = 1
	s1 := DeriveSessionID(k1)
	s2 := DeriveSessionID(k2)
	if s1 == s2 {
		t.Error("different keys produced the same session ID")
	}
}

// --- Epoch Key ---

func TestDeriveEpochKeyKnownAnswer(t *testing.T) {
	k := make([]byte, 32)
	for i := range k {
		k[i] = byte(i)
	}
	epoch := uint64(42)

	info := make([]byte, len(protocol.EpochKeyInfoPrefix)+8)
	copy(info, protocol.EpochKeyInfoPrefix)
	binary.BigEndian.PutUint64(info[len(protocol.EpochKeyInfoPrefix):], epoch)

	reader := hkdf.New(sha256.New, k, nil, info)
	want := make([]byte, protocol.KeyLen)
	if _, err := reader.Read(want); err != nil {
		t.Fatal(err)
	}

	got, err := DeriveEpochKey(k, epoch)
	if err != nil {
		t.Fatalf("DeriveEpochKey: %v", err)
	}
	defer ZeroBytes(got)
	if !bytes.Equal(got, want) {
		t.Errorf("epoch key mismatch\ngot:  %x\nwant: %x", got, want)
	}
}

func TestDeriveEpochKeyLength(t *testing.T) {
	k := make([]byte, 32)
	ek, err := DeriveEpochKey(k, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer ZeroBytes(ek)
	if len(ek) != protocol.KeyLen {
		t.Errorf("len = %d, want %d", len(ek), protocol.KeyLen)
	}
}

func TestDeriveEpochKeyDeterministic(t *testing.T) {
	k := make([]byte, 32)
	k[0] = 0x99
	e1, _ := DeriveEpochKey(k, 5)
	e2, _ := DeriveEpochKey(k, 5)
	defer ZeroBytes(e1)
	defer ZeroBytes(e2)
	if !bytes.Equal(e1, e2) {
		t.Error("same (key, epoch) produced different epoch keys")
	}
}

func TestDeriveEpochKeyDifferentEpochs(t *testing.T) {
	k := make([]byte, 32)
	e1, _ := DeriveEpochKey(k, 0)
	e2, _ := DeriveEpochKey(k, 1)
	defer ZeroBytes(e1)
	defer ZeroBytes(e2)
	if bytes.Equal(e1, e2) {
		t.Error("different epochs produced the same key")
	}
}

// --- AES-256-GCM ---

func TestSealOpenRoundTrip(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	nonce := make([]byte, 12)
	nonce[11] = 1

	plaintext := []byte("hello, lockwire!")
	ciphertext, err := Seal(key, nonce, plaintext)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	got, err := Open(key, nonce, ciphertext)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Errorf("round-trip failed: got %q, want %q", got, plaintext)
	}
}

func TestSealProducesDifferentCiphertext(t *testing.T) {
	key := make([]byte, 32)
	nonce1 := make([]byte, 12)
	nonce1[11] = 1
	nonce2 := make([]byte, 12)
	nonce2[11] = 2

	plaintext := []byte("same message")
	ct1, _ := Seal(key, nonce1, plaintext)
	ct2, _ := Seal(key, nonce2, plaintext)
	if bytes.Equal(ct1, ct2) {
		t.Error("different nonces produced identical ciphertext")
	}
}

func TestOpenRejectsTamperedCiphertext(t *testing.T) {
	key := make([]byte, 32)
	nonce := make([]byte, 12)
	nonce[11] = 1

	ct, _ := Seal(key, nonce, []byte("secret"))
	ct[0] ^= 0xff

	_, err := Open(key, nonce, ct)
	if err == nil {
		t.Error("expected error on tampered ciphertext")
	}
}

func TestOpenRejectsWrongKey(t *testing.T) {
	key1 := make([]byte, 32)
	key2 := make([]byte, 32)
	key2[0] = 1
	nonce := make([]byte, 12)
	nonce[11] = 1

	ct, _ := Seal(key1, nonce, []byte("secret"))
	_, err := Open(key2, nonce, ct)
	if err == nil {
		t.Error("expected error with wrong key")
	}
}

func TestSealRejectsInvalidKeyLength(t *testing.T) {
	_, err := Seal(make([]byte, 16), make([]byte, 12), []byte("data"))
	if err == nil {
		t.Error("expected error for 16-byte key")
	}
}

func TestSealRejectsInvalidNonceLength(t *testing.T) {
	_, err := Seal(make([]byte, 32), make([]byte, 8), []byte("data"))
	if err == nil {
		t.Error("expected error for 8-byte nonce")
	}
}

// NIST AES-256-GCM test vector (GCM Spec, Appendix B, Test Case 14)
// K=all zeros, IV=all zeros, P=all zeros (16 bytes), no AAD
func TestSealKnownAnswerNIST(t *testing.T) {
	key := make([]byte, 32)
	nonce := make([]byte, 12)
	plaintext := make([]byte, 16)
	wantCT, _ := hex.DecodeString("cea7403d4d606b6e074ec5d3baf39d18")
	wantTag, _ := hex.DecodeString("d0d1c8a799996bf0265b98b5d48ab919")

	ct, err := Seal(key, nonce, plaintext)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	gotCT := ct[:len(ct)-16]
	gotTag := ct[len(ct)-16:]

	if !bytes.Equal(gotCT, wantCT) {
		t.Errorf("ciphertext mismatch\ngot:  %x\nwant: %x", gotCT, wantCT)
	}
	if !bytes.Equal(gotTag, wantTag) {
		t.Errorf("tag mismatch\ngot:  %x\nwant: %x", gotTag, wantTag)
	}
}

// --- HKDF known-answer (RFC 5869, Test Case 1) ---

func TestDeriveEpochKeyHKDFCorrectness(t *testing.T) {
	ikm, _ := hex.DecodeString("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
	salt, _ := hex.DecodeString("000102030405060708090a0b0c")
	info, _ := hex.DecodeString("f0f1f2f3f4f5f6f7f8f9")
	wantOKM, _ := hex.DecodeString("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865")

	reader := hkdf.New(sha256.New, ikm, salt, info)
	got := make([]byte, 42)
	if _, err := reader.Read(got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, wantOKM) {
		t.Errorf("HKDF RFC 5869 test case 1 failed\ngot:  %x\nwant: %x", got, wantOKM)
	}
}

// --- Nonce Counter ---

func TestNonceCounterStartsAtOne(t *testing.T) {
	nc := NewNonceCounter()
	n := nc.Next()
	if len(n) != protocol.NonceLen {
		t.Errorf("nonce length = %d, want %d", len(n), protocol.NonceLen)
	}
	var val uint64
	for i := 4; i < 12; i++ {
		val = val<<8 | uint64(n[i])
	}
	if val != 1 {
		t.Errorf("first nonce counter = %d, want 1", val)
	}
}

func TestNonceCounterMonotonicallyIncreases(t *testing.T) {
	nc := NewNonceCounter()
	prev := uint64(0)
	for i := 0; i < 100; i++ {
		n := nc.Next()
		var val uint64
		for j := 4; j < 12; j++ {
			val = val<<8 | uint64(n[j])
		}
		if val <= prev {
			t.Fatalf("nonce not monotonic: %d <= %d at iteration %d", val, prev, i)
		}
		prev = val
	}
}

func TestNonceCounterConcurrentSafety(t *testing.T) {
	nc := NewNonceCounter()
	seen := make(map[uint64]bool)
	var mu sync.Mutex
	var wg sync.WaitGroup

	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			n := nc.Next()
			var val uint64
			for j := 4; j < 12; j++ {
				val = val<<8 | uint64(n[j])
			}
			mu.Lock()
			if seen[val] {
				t.Errorf("duplicate nonce: %d", val)
			}
			seen[val] = true
			mu.Unlock()
		}()
	}
	wg.Wait()

	if len(seen) != 100 {
		t.Errorf("expected 100 unique nonces, got %d", len(seen))
	}
}

// --- Viewer ID ---

func TestGenerateViewerIDFormat(t *testing.T) {
	for i := 0; i < 50; i++ {
		id, err := GenerateViewerID()
		if err != nil {
			t.Fatalf("GenerateViewerID: %v", err)
		}
		if len(id) != protocol.ViewerIDLen {
			t.Errorf("viewer ID length = %d, want %d", len(id), protocol.ViewerIDLen)
		}
		if !regexp.MustCompile(`^[a-z0-9]+$`).MatchString(id) {
			t.Errorf("viewer ID %q contains invalid characters", id)
		}
	}
}

func TestGenerateViewerIDUniqueness(t *testing.T) {
	seen := make(map[string]bool)
	for i := 0; i < 100; i++ {
		id, err := GenerateViewerID()
		if err != nil {
			t.Fatalf("GenerateViewerID: %v", err)
		}
		if seen[id] {
			t.Errorf("duplicate viewer ID: %s", id)
		}
		seen[id] = true
	}
}
