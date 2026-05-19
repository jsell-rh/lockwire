package main

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jsell-rh/lockwire/internal/protocol"
	"github.com/jsell-rh/lockwire/internal/relay"
)

func TestRelayClientConnectsAndReceivesAck(t *testing.T) {
	srv := relay.NewServer()
	ts := httptest.NewServer(srv)
	defer ts.Close()

	relayWS := "ws" + strings.TrimPrefix(ts.URL, "http")
	sessionID := "aabbccdd11223344aabbccdd11223344"

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	client, err := dialRelay(ctx, relayWS+"/api/share/"+sessionID, false)
	if err != nil {
		t.Fatalf("dialRelay: %v", err)
	}
	defer client.Close()

	// Should receive registration ack.
	data, err := client.Recv(ctx)
	if err != nil {
		t.Fatalf("Recv: %v", err)
	}

	if len(data) < 2 {
		t.Fatalf("control frame too short: %d bytes", len(data))
	}
	if data[0] != protocol.MsgTypeControl || data[1] != protocol.CtrlRegistrationAck {
		t.Errorf("expected CtrlRegistrationAck, got [0x%02x, 0x%02x]", data[0], data[1])
	}

	// Send heartbeat, expect pong.
	if err := client.Send(ctx, []byte{protocol.MsgTypeHeartbeat}); err != nil {
		t.Fatalf("Send heartbeat: %v", err)
	}

	pong, err := client.Recv(ctx)
	if err != nil {
		t.Fatalf("Recv pong: %v", err)
	}
	if len(pong) < 1 || pong[0] != protocol.MsgTypePong {
		t.Errorf("expected pong, got %v", pong)
	}
}
