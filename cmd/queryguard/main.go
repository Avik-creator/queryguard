// Command queryguard is a Postgres proxy that admits each tenant's queries by estimated cost.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Avik-creator/queryguard/pkg/plan"
	"github.com/Avik-creator/queryguard/pkg/policy"
	"github.com/Avik-creator/queryguard/pkg/proxy"
	"github.com/Avik-creator/queryguard/pkg/wire"
	"github.com/jackc/pgx/v5"
)

// version is set at build time with -ldflags "-X main.version=v0.1.0".
var version = "dev"

// options holds the command-line flags.
type options struct {
	listen          string
	upstream        string
	tlsCert         string
	tlsKey          string
	upstreamSSL     string
	upstreamCA      string
	clientCheck     time.Duration
	keepAlive       bool
	config          string
	catalogDSN      string
	shutdownTimeout time.Duration
}

func main() {
	var opts options
	flag.StringVar(&opts.listen, "listen", "127.0.0.1:6543", "address to accept client connections on")
	flag.StringVar(&opts.upstream, "upstream", "127.0.0.1:5418", "host:port of the Postgres server")
	flag.StringVar(&opts.tlsCert, "tls-cert", "", "PEM certificate for client TLS; needs -tls-key")
	flag.StringVar(&opts.tlsKey, "tls-key", "", "PEM private key for client TLS; needs -tls-cert")
	flag.StringVar(&opts.upstreamSSL, "upstream-sslmode", "disable", "TLS to Postgres: disable, require or verify-full")
	flag.StringVar(&opts.upstreamCA, "upstream-ca", "", "PEM CA certificates for verify-full; default is the system roots")
	flag.DurationVar(&opts.clientCheck, "client-check-interval", proxy.DefaultClientCheckInterval,
		"how often Postgres checks that a client is still there during a query; 0 leaves Postgres's setting alone")
	flag.StringVar(&opts.config, "config", "", "JSON policy file with rules and connection caps; none means no checks")
	flag.StringVar(&opts.catalogDSN, "catalog-dsn", "",
		"connection string for reading table sizes, needed by max_scan_rows; the password can come from PGPASSWORD or a .pgpass file")
	flag.BoolVar(&opts.keepAlive, "tcp-keepalive", true,
		"find silently dead clients and servers in about 30s; false keeps the operating system's timing")
	flag.DurationVar(&opts.shutdownTimeout, "shutdown-timeout", proxy.DefaultShutdownTimeout,
		"how long open sessions may continue after a shutdown signal")
	showVersion := flag.Bool("version", false, "print the version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Println("queryguard", version)
		return
	}

	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	if err := run(opts, log); err != nil {
		log.Error("queryguard stopped", "err", err)
		os.Exit(1)
	}
}

func run(opts options, log *slog.Logger) error {
	tlsConfig, err := loadTLS(opts.tlsCert, opts.tlsKey)
	if err != nil {
		return err
	}
	upstreamTLSConfig, err := upstreamTLS(opts.upstreamSSL, opts.upstreamCA, opts.upstream)
	if err != nil {
		return err
	}
	pol, err := loadPolicy(opts.config)
	if err != nil {
		return err
	}
	catalog, err := newCatalog(opts.catalogDSN, pol, log)
	if err != nil {
		return err
	}

	// Ctrl-C or a SIGTERM from Docker or systemd starts a clean shutdown.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	ln, err := net.Listen("tcp", opts.listen)
	if err != nil {
		return err
	}
	log.Info("queryguard started", "version", version, "listen", ln.Addr(), "upstream", opts.upstream,
		"tls", tlsConfig != nil, "upstream_sslmode", opts.upstreamSSL, "config", opts.config)

	var keepAlive net.KeepAliveConfig
	if opts.keepAlive {
		keepAlive = proxy.DefaultKeepAlive
	}
	s := &proxy.Server{
		Upstream:            proxy.Dialer{Addr: opts.upstream, TLSConfig: upstreamTLSConfig, KeepAlive: keepAlive},
		TLSConfig:           tlsConfig,
		ClientCheckInterval: opts.clientCheck,
		KeepAlive:           keepAlive,
		Policy:              pol,
		Catalog:             catalog,
		ShutdownTimeout:     opts.shutdownTimeout,
		Logger:              log,
	}
	if err := s.Serve(ctx, ln); err != nil {
		return err
	}
	log.Info("queryguard stopped cleanly")
	return nil
}

// loadPolicy reads the policy file, or returns nil when there is none.
func loadPolicy(path string) (*policy.Policy, error) {
	if path == "" {
		return nil, nil
	}
	return policy.Load(path)
}

// newCatalog returns the table-size reader for dsn, or nil without one, which a policy with max_scan_rows can't do without.
func newCatalog(dsn string, pol *policy.Policy, log *slog.Logger) (*plan.Catalog, error) {
	if dsn == "" {
		if pol != nil && pol.NeedsCatalog() {
			return nil, errors.New("rule max_scan_rows needs table sizes: set -catalog-dsn")
		}
		return nil, nil
	}
	if _, err := pgx.ParseConfig(dsn); err != nil {
		return nil, fmt.Errorf("-catalog-dsn: %w", err)
	}
	return &plan.Catalog{DSN: dsn, Log: log}, nil
}

// loadTLS returns the client TLS config, or nil when neither file is given.
func loadTLS(certFile, keyFile string) (*tls.Config, error) {
	if certFile == "" && keyFile == "" {
		return nil, nil
	}
	if certFile == "" || keyFile == "" {
		return nil, errors.New("-tls-cert and -tls-key must be given together")
	}
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("load TLS certificate: %w", err)
	}
	return wire.ServerTLSConfig(cert), nil
}

// upstreamTLS returns the TLS config for connecting to Postgres; sslmode names follow libpq.
func upstreamTLS(mode, caFile, addr string) (*tls.Config, error) {
	if caFile != "" && mode != "verify-full" {
		return nil, errors.New("-upstream-ca needs -upstream-sslmode=verify-full")
	}
	switch mode {
	case "disable":
		return nil, nil
	case "require":
		// Like libpq: encrypt, but accept any certificate.
		return &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: true}, nil
	case "verify-full":
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		cfg := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: host}
		if caFile != "" {
			pem, err := os.ReadFile(caFile)
			if err != nil {
				return nil, err
			}
			cfg.RootCAs = x509.NewCertPool()
			if !cfg.RootCAs.AppendCertsFromPEM(pem) {
				return nil, fmt.Errorf("no certificates found in %s", caFile)
			}
		}
		return cfg, nil
	default:
		return nil, fmt.Errorf("unknown -upstream-sslmode %q: want disable, require or verify-full", mode)
	}
}
