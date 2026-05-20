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
		listen        string
		certFile      string
		keyFile       string
		selfSigned    bool
		trustedProxy  []string
	)

	cmd := &cobra.Command{
		Use:          "relay",
		Short:        "Start the relay server",
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if selfSigned && (certFile != "" || keyFile != "") {
				return errors.New("--self-signed cannot be used with --tls-cert or --tls-key")
			}
			if !selfSigned {
				if certFile == "" && keyFile == "" {
					return errors.New("--tls-cert and --tls-key are required (or use --self-signed)")
				}
				if (certFile == "") != (keyFile == "") {
					return errors.New("--tls-cert and --tls-key must be used together")
				}
			}

			ctx, cancel := signal.NotifyContext(cmd.Context(), syscall.SIGINT, syscall.SIGTERM)
			defer cancel()

			if selfSigned {
				return startRelaySelfSigned(ctx, cmd, listen, trustedProxy)
			}
			return startRelay(ctx, cmd, listen, certFile, keyFile, trustedProxy)
		},
	}

	cmd.Flags().StringVar(&listen, "listen", ":8443", "address to listen on")
	cmd.Flags().StringVar(&certFile, "tls-cert", "", "path to TLS certificate file")
	cmd.Flags().StringVar(&keyFile, "tls-key", "", "path to TLS private key file")
	cmd.Flags().BoolVar(&selfSigned, "self-signed", false, "generate a self-signed TLS certificate at startup")
	cmd.Flags().StringSliceVar(&trustedProxy, "trusted-proxy", nil, "CIDR ranges to trust for X-Forwarded-For/CF-Connecting-IP (e.g. 127.0.0.0/8)")

	return cmd
}

func startRelay(ctx context.Context, cmd *cobra.Command, listen, certFile, keyFile string, proxyCIDRs []string) error {
	certPEM, err := os.ReadFile(certFile)
	if err != nil {
		return fmt.Errorf("could not load TLS certificate: %w", err)
	}
	keyPEM, err := os.ReadFile(keyFile)
	if err != nil {
		return fmt.Errorf("could not load TLS private key: %w", err)
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return fmt.Errorf("could not load TLS certificate: %w", err)
	}

	return serveRelay(ctx, cmd, listen, cert, "", proxyCIDRs)
}

func startRelaySelfSigned(ctx context.Context, cmd *cobra.Command, listen string, proxyCIDRs []string) error {
	cert, fingerprint, err := generateSelfSignedCert(listen)
	if err != nil {
		return fmt.Errorf("generating self-signed certificate: %w", err)
	}

	return serveRelay(ctx, cmd, listen, cert, fingerprint, proxyCIDRs)
}

func serveRelay(ctx context.Context, cmd *cobra.Command, listen string, cert tls.Certificate, fingerprint string, proxyCIDRs []string) error {
	probe := &logRelayProbe{out: os.Stderr}

	rl := relay.NewRateLimiter(relay.DefaultRateLimitConfig(), probe, time.Now)

	opts := []relay.Option{
		relay.WithWebAssets(web.Assets, version),
		relay.WithProbe(probe),
		relay.WithRateLimiter(rl),
	}
	if len(proxyCIDRs) > 0 {
		opts = append(opts, relay.WithTrustedProxies(proxyCIDRs))
	}

	srv := relay.NewServer(opts...)

	ln, err := net.Listen("tcp", listen)
	if err != nil {
		return fmt.Errorf("could not listen on %s: %w", listen, err)
	}

	tlsLn := tls.NewListener(ln, &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	})

	addr := tlsLn.Addr().String()
	if fingerprint != "" {
		fmt.Fprintf(cmd.ErrOrStderr(), "relay listening on %s (self-signed; use --relay-insecure to connect)\n", addr)
		fmt.Fprintf(cmd.ErrOrStderr(), "fingerprint: %s\n", fingerprint)
	} else {
		fmt.Fprintf(cmd.ErrOrStderr(), "relay listening on %s\n", addr)
	}
	fmt.Fprintf(cmd.ErrOrStderr(), "web viewer at https://%s/join\n", addr)

	httpSrv := &http.Server{
		Handler: srv,
	}

	notifyRelayAddr(addr)

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
