package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/jsell-rh/lockwire/internal/protocol"
)

func TestRelayCommandRegistered(t *testing.T) {
	root := newRootCmd("v0.0.0-test")
	found := false
	for _, c := range root.Commands() {
		if c.Name() == "relay" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("relay subcommand not registered on root")
	}
}

func TestRelayFlagDefaults(t *testing.T) {
	root := newRootCmd("v0.0.0-test")
	var relay *bytes.Buffer
	for _, c := range root.Commands() {
		if c.Name() == "relay" {
			relay = &bytes.Buffer{}
			c.SetOut(relay)
			listen, err := c.Flags().GetString("listen")
			if err != nil {
				t.Fatalf("getting --listen flag: %v", err)
			}
			if listen != ":8443" {
				t.Errorf("--listen default = %q, want %q", listen, ":8443")
			}
			break
		}
	}
	if relay == nil {
		t.Fatal("relay subcommand not found")
	}
}

func TestRelayRequiresTLSFlags(t *testing.T) {
	root := newRootCmd("v0.0.0-test")
	root.SetArgs([]string{"relay"})
	var stderr bytes.Buffer
	root.SetErr(&stderr)

	err := root.Execute()
	if err == nil {
		t.Fatal("expected error when --tls-cert and --tls-key are missing")
	}
	if !strings.Contains(err.Error(), "--self-signed") {
		t.Errorf("error should mention --self-signed, got: %v", err)
	}
}

func TestRelayInvalidCertFails(t *testing.T) {
	dir := t.TempDir()
	certFile := filepath.Join(dir, "bad.pem")
	keyFile := filepath.Join(dir, "bad-key.pem")
	os.WriteFile(certFile, []byte("not a cert"), 0o600)
	os.WriteFile(keyFile, []byte("not a key"), 0o600)

	root := newRootCmd("v0.0.0-test")
	root.SetArgs([]string{
		"relay",
		"--tls-cert", certFile,
		"--tls-key", keyFile,
	})

	err := root.Execute()
	if err == nil {
		t.Fatal("expected error for invalid cert/key")
	}
}

func TestRelayStartsAndServesHTTPS(t *testing.T) {
	certFile, keyFile := generateTestCert(t)

	root := newRootCmd("v0.0.0-test")
	root.SetArgs([]string{
		"relay",
		"--listen", "127.0.0.1:0",
		"--tls-cert", certFile,
		"--tls-key", keyFile,
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	addrCh := make(chan string, 1)
	setRelayAddrNotify(func(addr string) {
		addrCh <- addr
	})
	defer setRelayAddrNotify(nil)

	errCh := make(chan error, 1)
	go func() {
		errCh <- runRelayWithContext(ctx, root)
	}()

	var addr string
	select {
	case addr = <-addrCh:
	case err := <-errCh:
		t.Fatalf("relay exited early: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for relay to start")
	}

	certPEM, err := os.ReadFile(certFile)
	if err != nil {
		t.Fatalf("reading cert: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(certPEM)

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: pool},
		},
	}

	resp, err := client.Get("https://" + addr + "/join")
	if err != nil {
		t.Fatalf("GET /join: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("GET /join status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	cancel()

	select {
	case err := <-errCh:
		if err != nil {
			t.Errorf("relay returned error on shutdown: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("relay did not shut down within 5s")
	}
}

func TestRelayAcceptsWebSocketConnections(t *testing.T) {
	certFile, keyFile := generateTestCert(t)

	root := newRootCmd("v0.0.0-test")
	root.SetArgs([]string{
		"relay",
		"--listen", "127.0.0.1:0",
		"--tls-cert", certFile,
		"--tls-key", keyFile,
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	addrCh := make(chan string, 1)
	setRelayAddrNotify(func(addr string) {
		addrCh <- addr
	})
	defer setRelayAddrNotify(nil)

	errCh := make(chan error, 1)
	go func() {
		errCh <- runRelayWithContext(ctx, root)
	}()

	var addr string
	select {
	case addr = <-addrCh:
	case err := <-errCh:
		t.Fatalf("relay exited early: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for relay to start")
	}

	certPEM, err := os.ReadFile(certFile)
	if err != nil {
		t.Fatalf("reading cert: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(certPEM)

	dialCtx, dialCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer dialCancel()

	sessionID := "aabbccdd11223344aabbccdd11223344"
	wsConn, _, err := websocket.Dial(dialCtx, "wss://"+addr+"/api/share/"+sessionID, &websocket.DialOptions{
		HTTPClient: &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{RootCAs: pool},
			},
		},
	})
	if err != nil {
		t.Fatalf("WebSocket dial: %v", err)
	}
	defer wsConn.CloseNow()

	readCtx, readCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer readCancel()
	_, data, err := wsConn.Read(readCtx)
	if err != nil {
		t.Fatalf("reading registration ack: %v", err)
	}
	if len(data) < 2 || data[0] != protocol.MsgTypeControl || data[1] != protocol.CtrlRegistrationAck {
		t.Errorf("expected registration-ack, got %x", data)
	}

	cancel()
}

func TestRelayGracefulShutdown(t *testing.T) {
	certFile, keyFile := generateTestCert(t)

	root := newRootCmd("v0.0.0-test")
	root.SetArgs([]string{
		"relay",
		"--listen", "127.0.0.1:0",
		"--tls-cert", certFile,
		"--tls-key", keyFile,
	})

	ctx, cancel := context.WithCancel(context.Background())

	addrCh := make(chan string, 1)
	setRelayAddrNotify(func(addr string) {
		addrCh <- addr
	})
	defer setRelayAddrNotify(nil)

	errCh := make(chan error, 1)
	go func() {
		errCh <- runRelayWithContext(ctx, root)
	}()

	select {
	case <-addrCh:
	case err := <-errCh:
		t.Fatalf("relay exited early: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for relay to start")
	}

	cancel()

	select {
	case err := <-errCh:
		if err != nil {
			t.Errorf("expected clean shutdown, got: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("relay did not shut down within 5s")
	}
}

func TestRelaySelfSignedConflictsWithTLSCert(t *testing.T) {
	root := newRootCmd("v0.0.0-test")
	root.SetArgs([]string{"relay", "--self-signed", "--tls-cert", "/tmp/cert.pem"})

	err := root.Execute()
	if err == nil {
		t.Fatal("expected error when --self-signed used with --tls-cert")
	}
	want := "--self-signed cannot be used with --tls-cert or --tls-key"
	if !strings.Contains(err.Error(), want) {
		t.Errorf("error = %q, want substring %q", err.Error(), want)
	}
}

func TestRelaySelfSignedConflictsWithTLSKey(t *testing.T) {
	root := newRootCmd("v0.0.0-test")
	root.SetArgs([]string{"relay", "--self-signed", "--tls-key", "/tmp/key.pem"})

	err := root.Execute()
	if err == nil {
		t.Fatal("expected error when --self-signed used with --tls-key")
	}
	want := "--self-signed cannot be used with --tls-cert or --tls-key"
	if !strings.Contains(err.Error(), want) {
		t.Errorf("error = %q, want substring %q", err.Error(), want)
	}
}

func TestRelayOnlyTLSCertFails(t *testing.T) {
	root := newRootCmd("v0.0.0-test")
	root.SetArgs([]string{"relay", "--tls-cert", "/tmp/cert.pem"})

	err := root.Execute()
	if err == nil {
		t.Fatal("expected error when only --tls-cert provided")
	}
	want := "--tls-cert and --tls-key must be used together"
	if !strings.Contains(err.Error(), want) {
		t.Errorf("error = %q, want substring %q", err.Error(), want)
	}
}

func TestRelayOnlyTLSKeyFails(t *testing.T) {
	root := newRootCmd("v0.0.0-test")
	root.SetArgs([]string{"relay", "--tls-key", "/tmp/key.pem"})

	err := root.Execute()
	if err == nil {
		t.Fatal("expected error when only --tls-key provided")
	}
	want := "--tls-cert and --tls-key must be used together"
	if !strings.Contains(err.Error(), want) {
		t.Errorf("error = %q, want substring %q", err.Error(), want)
	}
}

func TestRelaySelfSignedStartsAndServes(t *testing.T) {
	root := newRootCmd("v0.0.0-test")
	root.SetArgs([]string{"relay", "--self-signed", "--listen", "127.0.0.1:0"})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	addrCh := make(chan string, 1)
	setRelayAddrNotify(func(addr string) {
		addrCh <- addr
	})
	defer setRelayAddrNotify(nil)

	errCh := make(chan error, 1)
	go func() {
		errCh <- runRelayWithContext(ctx, root)
	}()

	var addr string
	select {
	case addr = <-addrCh:
	case err := <-errCh:
		t.Fatalf("relay exited early: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for relay to start")
	}

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	resp, err := client.Get("https://" + addr + "/join")
	if err != nil {
		t.Fatalf("GET /join: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("GET /join status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	cancel()

	select {
	case err := <-errCh:
		if err != nil {
			t.Errorf("relay returned error on shutdown: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("relay did not shut down within 5s")
	}
}

func TestRelaySelfSignedPrintsFingerprint(t *testing.T) {
	root := newRootCmd("v0.0.0-test")
	var stderr bytes.Buffer
	root.SetErr(&stderr)
	root.SetArgs([]string{"relay", "--self-signed", "--listen", "127.0.0.1:0"})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	addrCh := make(chan string, 1)
	setRelayAddrNotify(func(addr string) {
		addrCh <- addr
	})
	defer setRelayAddrNotify(nil)

	errCh := make(chan error, 1)
	go func() {
		errCh <- runRelayWithContext(ctx, root)
	}()

	select {
	case <-addrCh:
	case err := <-errCh:
		t.Fatalf("relay exited early: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for relay to start")
	}

	// Give a moment for stderr output
	time.Sleep(50 * time.Millisecond)
	cancel()
	<-errCh

	output := stderr.String()
	if !strings.Contains(output, "fingerprint: SHA256:") {
		t.Errorf("stderr should contain fingerprint, got: %q", output)
	}

	// Fingerprint must use uppercase hex (spec: AA:BB:CC not aa:bb:cc)
	for _, line := range strings.Split(output, "\n") {
		if strings.HasPrefix(line, "fingerprint: SHA256:") {
			hex := strings.TrimPrefix(line, "fingerprint: SHA256:")
			if hex != strings.ToUpper(hex) {
				t.Errorf("fingerprint should use uppercase hex, got: %q", line)
			}
		}
	}

	if !strings.Contains(output, "self-signed") {
		t.Errorf("stderr should mention self-signed mode, got: %q", output)
	}
}

func TestRelaySelfSignedBothTLSFlagsConflict(t *testing.T) {
	root := newRootCmd("v0.0.0-test")
	root.SetArgs([]string{"relay", "--self-signed", "--tls-cert", "/tmp/cert.pem", "--tls-key", "/tmp/key.pem"})

	err := root.Execute()
	if err == nil {
		t.Fatal("expected error when --self-signed used with both --tls-cert and --tls-key")
	}
	want := "--self-signed cannot be used with --tls-cert or --tls-key"
	if !strings.Contains(err.Error(), want) {
		t.Errorf("error = %q, want substring %q", err.Error(), want)
	}
}

func TestSelfSignedCertProperties(t *testing.T) {
	cert, fingerprint, err := generateSelfSignedCert(":8443")
	if err != nil {
		t.Fatalf("generateSelfSignedCert: %v", err)
	}

	parsed, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatalf("parsing cert: %v", err)
	}

	// Valid for at least 1 year
	validity := parsed.NotAfter.Sub(parsed.NotBefore)
	if validity < 365*24*time.Hour {
		t.Errorf("cert validity = %v, want >= 1 year", validity)
	}

	// ECDSA P-256
	if parsed.PublicKeyAlgorithm != x509.ECDSA {
		t.Errorf("key algorithm = %v, want ECDSA", parsed.PublicKeyAlgorithm)
	}

	// Fingerprint format: SHA256: followed by uppercase colon-separated hex pairs
	if !strings.HasPrefix(fingerprint, "SHA256:") {
		t.Errorf("fingerprint should start with SHA256:, got %q", fingerprint)
	}
	hexPart := strings.TrimPrefix(fingerprint, "SHA256:")
	parts := strings.Split(hexPart, ":")
	if len(parts) != 32 {
		t.Errorf("fingerprint should have 32 hex pairs, got %d", len(parts))
	}
	for _, p := range parts {
		if len(p) != 2 || p != strings.ToUpper(p) {
			t.Errorf("fingerprint pair %q should be 2 uppercase hex chars", p)
		}
	}
}

func TestSelfSignedCertWildcardListenSAN(t *testing.T) {
	cert, _, err := generateSelfSignedCert(":8443")
	if err != nil {
		t.Fatalf("generateSelfSignedCert: %v", err)
	}

	parsed, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatalf("parsing cert: %v", err)
	}

	var hasIPv4Loopback, hasIPv6Loopback bool
	for _, ip := range parsed.IPAddresses {
		if ip.Equal(net.IPv4(127, 0, 0, 1)) {
			hasIPv4Loopback = true
		}
		if ip.Equal(net.IPv6loopback) {
			hasIPv6Loopback = true
		}
	}
	if !hasIPv4Loopback {
		t.Error("wildcard listen cert should include 127.0.0.1 SAN")
	}
	if !hasIPv6Loopback {
		t.Error("wildcard listen cert should include ::1 SAN")
	}
}

func TestSelfSignedCertExplicitHostSAN(t *testing.T) {
	cert, _, err := generateSelfSignedCert("relay.example.com:8443")
	if err != nil {
		t.Fatalf("generateSelfSignedCert: %v", err)
	}

	parsed, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatalf("parsing cert: %v", err)
	}

	found := false
	for _, name := range parsed.DNSNames {
		if name == "relay.example.com" {
			found = true
		}
	}
	if !found {
		t.Errorf("cert DNSNames = %v, want to include relay.example.com", parsed.DNSNames)
	}
}

func generateTestCert(t *testing.T) (certFile, keyFile string) {
	t.Helper()
	dir := t.TempDir()
	certFile = filepath.Join(dir, "cert.pem")
	keyFile = filepath.Join(dir, "key.pem")

	certPEM, keyPEM := selfSignedCert()
	if err := os.WriteFile(certFile, certPEM, 0o600); err != nil {
		t.Fatalf("writing cert: %v", err)
	}
	if err := os.WriteFile(keyFile, keyPEM, 0o600); err != nil {
		t.Fatalf("writing key: %v", err)
	}
	return certFile, keyFile
}
