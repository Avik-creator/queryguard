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
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/Avik-creator/queryguard/internal/safe"
	"github.com/Avik-creator/queryguard/pkg/fleet"
	"github.com/Avik-creator/queryguard/pkg/plan"
	"github.com/Avik-creator/queryguard/pkg/policy"
	"github.com/Avik-creator/queryguard/pkg/proxy"
	"github.com/Avik-creator/queryguard/pkg/session"
	"github.com/Avik-creator/queryguard/pkg/stats"
	"github.com/Avik-creator/queryguard/pkg/telemetry"
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
	metricsListen   string
	decisionLog     string
	reusePort       bool
}

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "admin":
			os.Exit(adminCLI(os.Args[2:], os.Stdout, os.Stderr))
		case "simulate":
			os.Exit(simulateCLI(os.Args[2:], os.Stdout, os.Stderr))
		case "test":
			os.Exit(testCLI(os.Args[2:], os.Stdout, os.Stderr))
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
	flag.StringVar(&opts.metricsListen, "metrics-listen", "",
		"address to serve Prometheus metrics on at /metrics, such as 127.0.0.1:9187; empty serves none")
	flag.StringVar(&opts.decisionLog, "decision-log", "",
		"JSON-lines file of every decision a rule made, such as a rejected statement; reopened on SIGHUP for log rotation")
	flag.BoolVar(&opts.reusePort, "reuse-port", false,
		"let other QueryGuard processes listen on -listen too (SO_REUSEPORT), so a new one takes connections while this one drains")
	flag.DurationVar(&opts.shutdownTimeout, "shutdown-timeout", proxy.DefaultShutdownTimeout,
		"after a shutdown signal, how long a session busy in a statement or transaction may go on; idle ones end at once")
	showVersion := flag.Bool("version", false, "print the version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Println("queryguard", version)
		return
	}

	log, metrics, decisions, err := newLogger(opts, os.Stderr)
	if err != nil {
		fmt.Fprintln(os.Stderr, "queryguard:", err)
		os.Exit(1)
	}
	err = run(opts, log, metrics, decisions)
	if decisions != nil {
		decisions.Close()
	}
	if err != nil {
		log.Error("queryguard stopped", "err", err)
		os.Exit(1)
	}
}

// newLogger returns the logger, writing to console, with the metrics registry and decision log the flags ask for; each may be nil.
func newLogger(opts options, console io.Writer) (*slog.Logger, *telemetry.Registry, *telemetry.File, error) {
	var metrics *telemetry.Registry
	if opts.metricsListen != "" {
		metrics = &telemetry.Registry{}
		metrics.Gauge("queryguard_build_info", "Always 1, labelled with the running version.", func(emit func(float64, ...string)) { emit(1, version) }, "version")
	}
	var decisions *telemetry.File
	var decisionLog slog.Handler
	if opts.decisionLog != "" {
		f, err := telemetry.OpenFile(opts.decisionLog)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("-decision-log: %w", err)
		}
		decisions, decisionLog = f, slog.NewJSONHandler(f, nil)
	}
	handler := slog.Handler(slog.NewTextHandler(console, nil))
	if metrics != nil || decisionLog != nil {
		handler = telemetry.NewDecisions(handler, metrics, decisionLog)
	}
	return slog.New(handler), metrics, decisions, nil
}

func run(opts options, log *slog.Logger, metrics *telemetry.Registry, decisions *telemetry.File) error {
	hup := catchHangups()
	certs, err := loadCertificates(opts.tlsCert, opts.tlsKey, opts.requireTLS)
	if err != nil {
		return err
	}
	var tlsConfig *tls.Config
	if certs != nil {
		tlsConfig = certs.tlsConfig()
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

	ln, err := proxy.Listen(ctx, opts.listen, opts.reusePort)
	if err != nil {
		return err
	}
	for _, w := range tlsWarnings(opts) {
		log.Warn(w)
	}
	if metrics != nil {
		stopMetrics, err := serveMetrics(opts.metricsListen, metrics, log)
		if err != nil {
			ln.Close()
			return err
		}
		defer stopMetrics()
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
		Metrics:             metrics,
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
	stopHangup := onHangup(hup, log, func() { hangup(s, opts.config, catalog, certs, decisions, log) })
	defer stopHangup()
	if err := s.Serve(ctx, ln); err != nil {
		return err
	}
	log.Info("queryguard stopped cleanly")
	return nil
}

// serveMetrics serves metrics at /metrics on addr until stop is called.
func serveMetrics(addr string, metrics *telemetry.Registry, log *slog.Logger) (stop func(), err error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("-metrics-listen: %w", err)
	}
	mux := http.NewServeMux()
	mux.Handle("GET /metrics", metrics)
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second, WriteTimeout: 30 * time.Second}
	go func() {
		if err := srv.Serve(ln); !errors.Is(err, http.ErrServerClosed) {
			log.Error("metrics server stopped", "err", err)
		}
	}()
	log.Info("serving metrics", "addr", ln.Addr())
	return func() { srv.Close() }, nil
}

// loadPolicy reads the policy file, or returns nil when there is none.
func loadPolicy(path string) (*policy.Policy, error) {
	if path == "" {
		// An empty policy checks nothing, not even DDL's locks, but gives sessions a checker for the kill switch.
		return policy.Parse([]byte(`{"ddl_guard": {"mode": "off"}}`))
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

// saveAllowlistEvery saves the allowlist whenever it has learned something, until ctx ends; a failed save is tried again.
func saveAllowlistEvery(ctx context.Context, list *policy.Allowlist, path string, log *slog.Logger) {
	tick := time.Tick(allowlistSaveInterval)
	unsaved := false
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick:
		}
		if unsaved = list.Changed() || unsaved; unsaved {
			if err := saveAllowlist(list, path); err != nil {
				log.Error("save allowlist", "file", path, "err", err)
				continue
			}
			unsaved = false
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
	allowlist := flags.String("allowlist", "", "QueryGuard's -allowlist-file, to replay the allowlist against")
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
	found := false
	for _, path := range []string{*traffic + ".1", *traffic} {
		recs, skipped, err := stats.ReadTraffic(path)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		if skipped > 0 {
			fmt.Fprintf(stderr, "%s: skipped %d lines that aren't records\n", path, skipped)
		}
		found = true
		records = append(records, recs...)
	}
	if !found {
		fmt.Fprintf(stderr, "no traffic log at %s\n", *traffic)
		return 1
	}
	var list *policy.Allowlist
	if *allowlist != "" {
		list = &policy.Allowlist{}
		if err := loadAllowlist(list, *allowlist); err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
	}
	sim := policy.Simulate(p, list, records)

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

// testCLI checks a config, and the statements in each corpus file against it, printing every case it gets wrong.
func testCLI(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("queryguard test", flag.ContinueOnError)
	flags.SetOutput(stderr)
	config := flags.String("config", "", "the config to check")
	role := flags.String("role", "agent", "the role the statements run as")
	database := flags.String("database", "postgres", "the database they run in")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if *config == "" {
		fmt.Fprintln(stderr, "usage: queryguard test -config config.json [-role name] [corpus.sql ...]")
		return 2
	}
	p, err := policy.Load(*config)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	if flags.NArg() == 0 {
		fmt.Fprintln(stdout, *config+": config is valid")
		return 0
	}
	if p.HasCostRules() {
		fmt.Fprintln(stdout, "not checked: cost rules (max_cost, max_scan_rows), which need each statement's plan from a server")
	}
	c := p.Checker(*role, slog.New(slog.DiscardHandler))
	c.Env = policy.Env{Database: *database}
	passed, failed := 0, 0
	for _, path := range flags.Args() {
		cases, err := readCases(path)
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		for _, tc := range cases {
			got := "allow"
			if rej, _ := c.Check(tc.sql, session.Settings{StandardConformingStrings: "on", ClientEncoding: "UTF8"}); rej != nil {
				got = "reject (" + policy.RuleName(rej.Message) + ")"
			}
			want := tc.want
			if tc.rule != "" {
				want += " " + tc.rule
			}
			ok := got == "allow" == (tc.want == "allow") && (tc.rule == "" || got == "reject ("+tc.rule+")")
			if ok {
				passed++
				continue
			}
			failed++
			fmt.Fprintf(stdout, "%s:%d: want %s, got %s: %s\n", path, tc.line, want, got, strings.Join(strings.Fields(tc.sql), " "))
		}
	}
	fmt.Fprintf(stdout, "%d passed, %d failed\n", passed, failed)
	if failed > 0 {
		return 1
	}
	return 0
}

// testCase is one statement of a corpus file and what the config should do with it.
type testCase struct {
	line int    // where its text starts
	want string // reject or allow
	rule string // the rule that should reject it; "" means any
	sql  string
}

// readCases reads a corpus file: each case is a line "-- reject [rule]" or "-- allow", then the statement's text up to the next such line.
func readCases(path string) ([]testCase, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cases []testCase
	for i, line := range strings.Split(string(data), "\n") {
		marker, isMarker := strings.CutPrefix(strings.TrimSpace(line), "-- ")
		fields := strings.Fields(marker)
		if isMarker && len(fields) > 0 && len(fields) <= 2 && (fields[0] == "reject" || fields[0] == "allow" && len(fields) == 1) {
			tc := testCase{want: fields[0]}
			if len(fields) == 2 {
				tc.rule = fields[1]
			}
			cases = append(cases, tc)
			continue
		}
		if len(cases) == 0 {
			continue
		}
		tc := &cases[len(cases)-1]
		if tc.sql == "" && strings.TrimSpace(line) != "" {
			tc.line = i + 1
		}
		if tc.sql != "" || strings.TrimSpace(line) != "" {
			tc.sql += line + "\n"
		}
	}
	for i := range cases {
		cases[i].sql = strings.TrimSpace(cases[i].sql)
		if cases[i].sql == "" {
			return nil, fmt.Errorf("%s: a %s case has no statement", path, cases[i].want)
		}
	}
	return cases, nil
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

// certificates holds the client TLS certificate, which a SIGHUP reads again from its files.
type certificates struct {
	certFile, keyFile string
	current           atomic.Pointer[tls.Certificate]
}

// loadCertificates reads the client TLS certificate, or returns nil when neither file is given, which require forbids.
func loadCertificates(certFile, keyFile string, require bool) (*certificates, error) {
	if certFile == "" && keyFile == "" {
		if require {
			return nil, errors.New("-require-client-tls needs -tls-cert and -tls-key")
		}
		return nil, nil
	}
	if certFile == "" || keyFile == "" {
		return nil, errors.New("-tls-cert and -tls-key must be given together")
	}
	c := &certificates{certFile: certFile, keyFile: keyFile}
	if err := c.reload(); err != nil {
		return nil, err
	}
	return c, nil
}

// reload reads the certificate files again, keeping the certificate in force when they don't load.
func (c *certificates) reload() error {
	cert, err := tls.LoadX509KeyPair(c.certFile, c.keyFile)
	if err != nil {
		return fmt.Errorf("load TLS certificate: %w", err)
	}
	c.current.Store(&cert)
	return nil
}

// tlsConfig returns a config for client TLS that offers whichever certificate was loaded last.
func (c *certificates) tlsConfig() *tls.Config {
	cfg := wire.ServerTLSConfig(tls.Certificate{})
	cfg.Certificates = nil
	cfg.GetCertificate = func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return c.current.Load(), nil }
	return cfg
}

// tlsWarnings names each connection to Postgres that doesn't check the server's certificate.
func tlsWarnings(opts options) []string {
	var warnings []string
	if opts.upstreamSSL == "require" {
		warnings = append(warnings, "-upstream-sslmode=require encrypts but accepts any certificate, so a man in the middle can read every login; use verify-full")
	}
	for _, dsn := range []struct{ flag, value string }{{"-catalog-dsn", opts.catalogDSN}, {"-state-dsn", opts.stateDSN}} {
		if dsn.value != "" && !verifiesServer(dsn.value) {
			warnings = append(warnings, dsn.flag+" may send its password where a man in the middle can read it; add sslmode=verify-full")
		}
	}
	return warnings
}

// verifiesServer reports whether dsn reaches Postgres over a Unix socket, or only over TLS with the server's certificate and name checked.
func verifiesServer(dsn string) bool {
	cfg, err := pgx.ParseConfig(dsn)
	if err != nil || strings.HasPrefix(cfg.Host, "/") {
		return true
	}
	// Only verify-full has no plaintext fallback and leaves Go's own checks on; verify-ca turns them off for a check of its own.
	verified := func(t *tls.Config) bool { return t != nil && !t.InsecureSkipVerify }
	if !verified(cfg.TLSConfig) {
		return false
	}
	for _, fb := range cfg.Fallbacks {
		if !verified(fb.TLSConfig) {
			return false
		}
	}
	return true
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

// catchHangups starts catching SIGHUP, which by Go's default ends the process, keeping one for onHangup to handle.
func catchHangups() chan os.Signal {
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	return hup
}

// onHangup runs f at each SIGHUP caught on hup until stop is called.
func onHangup(hup chan os.Signal, log *slog.Logger, f func()) (stop func()) {
	done := make(chan struct{})
	go safe.Loop(context.Background(), log, "SIGHUP", func(context.Context) {
		for {
			select {
			case <-done:
				return
			case <-hup:
				f()
			}
		}
	})
	return sync.OnceFunc(func() {
		signal.Stop(hup)
		close(done)
	})
}

// hangup reopens the decision log and reloads the client TLS certificate and the policy file, whichever QueryGuard has,
// each keeping the one in force when it fails.
func hangup(s *proxy.Server, config string, catalog *plan.Catalog, certs *certificates, decisions *telemetry.File, log *slog.Logger) {
	if certs == nil && config == "" && decisions == nil {
		log.Info("SIGHUP ignored: no -config, -tls-cert or -decision-log to reload")
		return
	}
	if decisions != nil {
		if err := decisions.Reopen(); err != nil {
			log.Error("decision log not reopened; the old file stays", "err", err)
		}
	}
	if certs != nil {
		if err := certs.reload(); err != nil {
			log.Error("TLS certificate not reloaded; the one in force stays", "err", err)
		} else {
			log.Info("TLS certificate reloaded", "cert", certs.certFile)
		}
	}
	if config != "" {
		if err := reload(s, config, catalog); err != nil {
			log.Error("config not reloaded; the one in force stays", "config", config, "err", err)
			return
		}
		log.Info("config reloaded", "config", config)
	}
}
