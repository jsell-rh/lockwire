package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"

	"github.com/coder/websocket"
)

type relayClient struct {
	conn *websocket.Conn
}

func dialRelay(ctx context.Context, url string, insecure bool) (*relayClient, error) {
	opts := &websocket.DialOptions{}
	if insecure {
		opts.HTTPClient = &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			},
		}
	}

	conn, _, err := websocket.Dial(ctx, url, opts)
	if err != nil {
		return nil, fmt.Errorf("connecting to relay: %w", err)
	}
	return &relayClient{conn: conn}, nil
}

func (c *relayClient) Send(ctx context.Context, msg []byte) error {
	return c.conn.Write(ctx, websocket.MessageBinary, msg)
}

func (c *relayClient) Recv(ctx context.Context) ([]byte, error) {
	_, data, err := c.conn.Read(ctx)
	return data, err
}

func (c *relayClient) Close() error {
	return c.conn.Close(websocket.StatusNormalClosure, "session ended")
}
