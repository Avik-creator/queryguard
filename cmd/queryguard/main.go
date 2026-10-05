// Command queryguard is a Postgres proxy that admits each tenant's queries by estimated cost.
package main

import (
	"cmp"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"maps"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/Avik-creator/queryguard/internal/safe"
	"github.com/Avik-creator/queryguard/pkg/fleet"
	"github.com/Avik-creator/queryguard/pkg/plan"
	"github.com/Avik-creator/queryguard/pkg/policy"
	"github.com/Avik-creator/queryguard/pkg/proxy"
	"github.com/Avik-creator/queryguard/pkg/stats"
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
	requireTLS      bool
	upstreamSSL     string
	upstreamCA      string
	clientCheck     time.Duration
	keepAlive       bool
	config          string
	catalogDSN      string
	stateDSN        string
	advertiseAddr   string
	maxInstances    int
	shutdownTimeout time.Duration
	statsMax        int
	statsErrorText  bool
	adminDB         string
	adminAuthDB     string
	allowlistFile   string
	trafficLog      string
}

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "admin":
			os.Exit(adminCLI(os.Args[2:], os.Stdout, os.Stderr))
		case "simulate":
			os.Exit(simulateCLI(os.Args[2:], os.Stdout, os.Stderr))
		}
	}
	var opts options
	flag.StringVar(&opts.listen, "listen", "127.0.0.1:6543", "address to accept client connections on")
	flag.StringVar(&opts.upstream, "upstream", "127.0.0.1:5418", "host:port of the Postgres server")
	flag.StringVar(&opts.tlsCert, "tls-cert", "", "PEM certificate for client TLS; needs -tls-key")
	flag.StringVar(&opts.tlsKey, "tls-key", "", "PEM private key for client TLS; needs -tls-cert")
	flag.BoolVar(&opts.requireTLS, "require-client-tls", false,
		"refuse logins without TLS, which pg_hba.conf can't do since PostgreSQL sees only the proxy; needs -tls-cert")
	flag.StringVar(&opts.upstreamSSL, "upstream-sslmode", "disable", "TLS to Postgres: disable, require or verify-full")
	flag.StringVar(&opts.upstreamCA, "upstream-ca", "", "PEM CA certificates for verify-full; default is the system roots")
	flag.DurationVar(&opts.clientCheck, "client-check-interval", proxy.DefaultClientCheckInterval,
		"how often Postgres checks that a client is still there during a query; 0 leaves Postgres's setting alone")
	flag.StringVar(&opts.config, "config", "", "JSON policy file with rules and connection caps; none means no checks")
	flag.StringVar(&opts.catalogDSN, "catalog-dsn", "",
		"connection string for a pg_monitor role that reads table sizes (needed by max_scan_rows) and the server's activity; the password can come from PGPASSWORD or a .pgpass file")
	flag.StringVar(&opts.stateDSN, "state-dsn", "",
		"connection string for a database set aside for QueryGuard, where instances in front of one server share budgets and slots")
	flag.StringVar(&opts.advertiseAddr, "advertise-addr", "",
		"host:port other instances reach this one on, to forward cancel requests; default is -listen")
	flag.IntVar(&opts.maxInstances, "max-instances", fleet.DefaultMaxInstances,
		"the most instances sharing -state-dsn; each falls back to this share of a limit while the store is unreachable")
	flag.BoolVar(&opts.keepAlive, "tcp-keepalive", true,
		"find silently dead clients and servers in about 30s; false keeps the operating system's timing")
	flag.IntVar(&opts.statsMax, "stats-max", stats.DefaultMax,
		"statement fingerprints, by tenant, whose calls, times and errors are kept; the least called goes first; 0 keeps none")
	flag.BoolVar(&opts.statsErrorText, "stats-error-text", false,
		"keep each statement's last error text with its stats; off by default since error text can carry row values")
	flag.StringVar(&opts.adminDB, "admin-db", "queryguard_admin",
		"database name that opens the admin console (psql -d queryguard_admin) for superusers and admin_roles; empty turns it off")
	flag.StringVar(&opts.adminAuthDB, "admin-auth-db", proxy.DefaultAdminAuthDatabase,
		"real database a console login is checked against by Postgres")
	flag.StringVar(&opts.allowlistFile, "allowlist-file", "",
		"JSON file the learned allowlist is read from at start and saved to as it learns")
	flag.StringVar(&opts.trafficLog, "traffic-log", "",
		"JSON-lines file of every statement, without its values, kept for a day or two, for queryguard simulate; needs -stats-max above 0")
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
	tlsConfig, err := loadTLS(opts.tlsCert, opts.tlsKey, opts.requireTLS)
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
	fl, err := newFleet(opts.stateDSN, opts.advertiseAddr, opts.listen, opts.maxInstances)
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
		"tls", tlsConfig != nil, "require_client_tls", opts.requireTLS, "upstream_sslmode", opts.upstreamSSL, "config", opts.config)

	var keepAlive net.KeepAliveConfig
	if opts.keepAlive {
		keepAlive = proxy.DefaultKeepAlive
	}
	s := &proxy.Server{
		Upstream:            proxy.Dialer{Addr: opts.upstream, TLSConfig: upstreamTLSConfig, KeepAlive: keepAlive},
		TLSConfig:           tlsConfig,
		RequireClientTLS:    opts.requireTLS,
		ClientCheckInterval: opts.clientCheck,
		KeepAlive:           keepAlive,
		Policy:              pol,
		Catalog:             catalog,
		Fleet:               fl,
		ShutdownTimeout:     opts.shutdownTimeout,
		Logger:              log,
	}
	if fl != nil {
		fl.Log = log
	}
	if opts.statsMax > 0 {
		s.Stats = &stats.Table{Max: opts.statsMax, ErrorText: opts.statsErrorText}
		if opts.trafficLog != "" {
			s.Stats.Traffic = &stats.TrafficLog{Path: opts.trafficLog, Log: log}
			defer s.Stats.Traffic.Close()
		}
	}
	s.AdminDatabase, s.AdminAuthDatabase = opts.adminDB, opts.adminAuthDB
	if opts.config != "" {
		s.Reload = func() error { return reload(s, opts.config, catalog) }
	}
	if opts.allowlistFile != "" {
		if err := loadAllowlist(&s.Allowlist, opts.allowlistFile); err != nil {
			return err
		}
		go safe.Loop(ctx, log, "allowlist", func(ctx context.Context) { saveAllowlistEvery(ctx, &s.Allowlist, opts.allowlistFile, log) })
		defer func() {
			if err := saveAllowlist(&s.Allowlist, opts.allowlistFile); err != nil {
				log.Error("save allowlist", "file", opts.allowlistFile, "err", err)
			}
		}()
	}
	s.Monitor = newMonitor(catalog, s, log)
	if opts.config != "" {
		go safe.Loop(ctx, log, "config reload", func(ctx context.Context) { reloadOnHangup(ctx, s, opts.config, catalog, log) })
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
		// An empty policy checks nothing, but gives sessions a checker for the kill switch.
		return policy.Parse([]byte("{}"))
	}
	return policy.Load(path)
}

// loadAllowlist reads the allowlist from path; a file that isn't there yet leaves it empty.
func loadAllowlist(list *policy.Allowlist, path string) error {
	f, err := os.Open(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer f.Close()
	if err := list.Load(f); err != nil {
		return fmt.Errorf("read allowlist %s: %w", path, err)
	}
	return nil
}

// saveAllowlist writes the allowlist to path through a temporary file, so a crash never leaves half of one.
func saveAllowlist(list *policy.Allowlist, path string) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".allowlist-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if err := list.Save(f); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), path)
}

// allowlistSaveInterval is how often a changed allowlist is saved.
const allowlistSaveInterval = 10 * time.Second

// saveAllowlistEvery saves the allowlist whenever it has learned something, until ctx ends.
func saveAllowlistEvery(ctx context.Context, list *policy.Allowlist, path string, log *slog.Logger) {
	tick := time.Tick(allowlistSaveInterval)
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick:
		}
		if list.Changed() {
			if err := saveAllowlist(list, path); err != nil {
				log.Error("save allowlist", "file", path, "err", err)
			}
		}
	}
}

// adminCLI runs one admin console command, such as "show stats" or "kill tenant acme for 10m", and prints its answer.
func adminCLI(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("queryguard admin", flag.ContinueOnError)
	flags.SetOutput(stderr)
	addr := flags.String("addr", "127.0.0.1:6543", "host:port QueryGuard listens on")
	user := flags.String("user", cmp.Or(os.Getenv("PGUSER"), "postgres"), "a superuser or admin role; the password comes from PGPASSWORD or .pgpass")
	db := flags.String("db", "queryguard_admin", "QueryGuard's -admin-db")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if flags.NArg() == 0 {
		fmt.Fprintln(stderr, "usage: queryguard admin [-addr host:port] [-user role] [-db name] command, such as: show stats")
		return 2
	}
	host, port, err := net.SplitHostPort(*addr)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, fmt.Sprintf("host=%s port=%s user=%s dbname=%s", host, port, *user, *db))
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	defer conn.Close(ctx)
	// The console takes simple queries only.
	rows, err := conn.Query(ctx, strings.Join(flags.Args(), " "), pgx.QueryExecModeSimpleProtocol)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	var columns []string
	for _, f := range rows.FieldDescriptions() {
		columns = append(columns, f.Name)
	}
	var table [][]string
	for rows.Next() {
		var row []string
		for _, v := range rows.RawValues() {
			row = append(row, string(v))
		}
		table = append(table, row)
	}
	if err := rows.Err(); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	if columns == nil {
		fmt.Fprintln(stdout, rows.CommandTag().String())
		return 0
	}
	printTable(stdout, columns, table)
	return 0
}

// simulateCLI replays the traffic log against a config and prints what it would have refused that ran, and the other way round.
func simulateCLI(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("queryguard simulate", flag.ContinueOnError)
	flags.SetOutput(stderr)
	config := flags.String("config", "", "the config to try")
	traffic := flags.String("traffic", "", "QueryGuard's -traffic-log; the file before it, with .1 added, is read too")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if *config == "" || *traffic == "" {
		fmt.Fprintln(stderr, "usage: queryguard simulate -config new.json -traffic traffic.jsonl")
		return 2
	}
	p, err := policy.Load(*config)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	var records []stats.Record
	for _, path := range []string{*traffic + ".1", *traffic} {
		recs, err := stats.ReadTraffic(path)
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			fmt.Fprintln(stderr, err)
			return 1
		}
		records = append(records, recs...)
	}
	sim := policy.Simulate(p, records)

	fmt.Fprintf(stdout, "%d statements from %s to %s\n\n", sim.Statements, sim.From.Format(time.RFC3339), sim.To.Format(time.RFC3339))
	var rules [][]string
	for _, name := range slices.Sorted(maps.Keys(sim.Rules)) {
		r := sim.Rules[name]
		rules = append(rules, []string{name, strconv.Itoa(r.Count), strings.Join(r.Examples, "; ")})
	}
	if rules != nil {
		printTable(stdout, []string{"refused by", "statements", "such as"}, rules)
		fmt.Fprintln(stdout)
	}
	var budgets [][]string
	for _, tenant := range slices.Sorted(maps.Keys(sim.Budgets)) {
		b := sim.Budgets[tenant]
		budgets = append(budgets, []string{tenant, strconv.Itoa(b.Rejected), strconv.Itoa(b.Waited), b.Wait.String(), strconv.Itoa(b.Slowed)})
	}
	if budgets != nil {
		printTable(stdout, []string{"tenant", "over budget, refused", "waited", "waited in all", "sent to the slow lane"}, budgets)
		fmt.Fprintln(stdout)
	}
	fmt.Fprintf(stdout, "newly rejected: %d\nno longer rejected: %d\n", sim.NewlyRejected, sim.NoLongerRejected)
	for _, n := range sim.NotSimulated {
		fmt.Fprintf(stdout, "not simulated: %s\n", n)
	}
	return 0
}

// printTable writes columns and rows as text, each column as wide as its widest cell.
func printTable(w io.Writer, columns []string, rows [][]string) {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, strings.Join(columns, "\t"))
	for _, row := range rows {
		fmt.Fprintln(tw, strings.Join(row, "\t"))
	}
	tw.Flush()
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

// newFleet returns the fleet stored at dsn, advertising advertise or else listen to its peers, or nil without a dsn.
func newFleet(dsn, advertise, listen string, maxInstances int) (*fleet.Fleet, error) {
	if dsn == "" {
		return nil, nil
	}
	if _, err := pgx.ParseConfig(dsn); err != nil {
		return nil, fmt.Errorf("-state-dsn: %w", err)
	}
	addr := cmp.Or(advertise, listen)
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("-advertise-addr: %w", err)
	}
	if ip := net.ParseIP(host); host == "" || ip != nil && ip.IsUnspecified() {
		return nil, fmt.Errorf("-listen %s names no one address other instances can reach: set -advertise-addr", listen)
	}
	return &fleet.Fleet{Store: &fleet.Postgres{DSN: dsn}, Addr: addr, MaxInstances: maxInstances}, nil
}

// newMonitor returns the reader of the server's activity over the catalog's connection string, watching the tables of s's policy,
// or nil without a catalog.
func newMonitor(catalog *plan.Catalog, s *proxy.Server, log *slog.Logger) proxy.Monitor {
	if catalog == nil {
		return nil
	}
	return &plan.Monitor{DSN: catalog.DSN, Log: log, Watch: func() []plan.Table {
		if p := s.ActivePolicy(); p != nil {
			return p.Watched()
		}
		return nil
	}}
}

// loadTLS returns the client TLS config, or nil when neither file is given, which require forbids.
func loadTLS(certFile, keyFile string, require bool) (*tls.Config, error) {
	if certFile == "" && keyFile == "" {
		if require {
			return nil, errors.New("-require-client-tls needs -tls-cert and -tls-key")
		}
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

// reload reads the policy file again and puts it in force for every session, keeping the one in force when it fails.
func reload(s *proxy.Server, path string, catalog *plan.Catalog) error {
	p, err := policy.Load(path)
	if err != nil {
		return err
	}
	if p.NeedsCatalog() && catalog == nil {
		return errors.New("rule max_scan_rows needs table sizes: restart with -catalog-dsn")
	}
	s.SetPolicy(p)
	return nil
}

// reloadOnHangup reloads the policy file at each SIGHUP until ctx ends.
func reloadOnHangup(ctx context.Context, s *proxy.Server, path string, catalog *plan.Catalog, log *slog.Logger) {
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	defer signal.Stop(hup)
	for {
		select {
		case <-ctx.Done():
			return
		case <-hup:
		}
		if err := reload(s, path, catalog); err != nil {
			log.Error("config not reloaded; the one in force stays", "config", path, "err", err)
			continue
		}
		log.Info("config reloaded", "config", path)
	}
}
