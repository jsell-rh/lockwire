package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/jsell-rh/lockwire/internal/relay"
	"github.com/jsell-rh/lockwire/web"
	"github.com/spf13/cobra"
)

var (
	relayAddrMu     sync.Mutex
	relayAddrNotify func(string)
)

func setRelayAddrNotify(fn func(string)) {
	relayAddrMu.Lock()
	relayAddrNotify = fn
	relayAddrMu.Unlock()
}

func notifyRelayAddr(addr string) {
	relayAddrMu.Lock()
	fn := relayAddrNotify
	relayAddrMu.Unlock()
	if fn != nil {
		fn(addr)
	}
}

func newRelayCmd() *cobra.Command {
	var (
		listen  string
		certFile string
		keyFile  string
	)

	cmd := &cobra.Command{
		Use:          "relay",
		Short:        "Start the relay server",
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if certFile == "" || keyFile == "" {
				return errors.New("--tls-cert and --tls-key are required")
			}

			ctx, cancel := signal.NotifyContext(cmd.Context(), syscall.SIGINT, syscall.SIGTERM)
			defer cancel()

			return startRelay(ctx, listen, certFile, keyFile)
		},
	}

	cmd.Flags().StringVar(&listen, "listen", ":8443", "address to listen on")
	cmd.Flags().StringVar(&certFile, "tls-cert", "", "path to TLS certificate file")
	cmd.Flags().StringVar(&keyFile, "tls-key", "", "path to TLS private key file")

	return cmd
}

func startRelay(ctx context.Context, listen, certFile, keyFile string) error {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return fmt.Errorf("loading TLS certificate: %w", err)
	}

	probe := &logRelayProbe{out: os.Stderr}

	rl := relay.NewRateLimiter(relay.DefaultRateLimitConfig(), probe, time.Now)

	srv := relay.NewServer(
		relay.WithWebAssets(web.Assets),
		relay.WithProbe(probe),
		relay.WithRateLimiter(rl),
	)

	ln, err := net.Listen("tcp", listen)
	if err != nil {
		return fmt.Errorf("listening on %s: %w", listen, err)
	}

	tlsLn := tls.NewListener(ln, &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	})

	httpSrv := &http.Server{
		Handler: srv,
	}

	notifyRelayAddr(tlsLn.Addr().String())

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		httpSrv.Shutdown(shutdownCtx)
	}()

	err = httpSrv.Serve(tlsLn)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func runRelayWithContext(ctx context.Context, root *cobra.Command) error {
	root.SetContext(ctx)
	return root.Execute()
}
