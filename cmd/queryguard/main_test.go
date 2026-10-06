package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"io"
	"log/slog"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"testing/synctest"
	"time"

	"github.com/Avik-creator/queryguard/internal/testcert"
	"github.com/Avik-creator/queryguard/pkg/plan"
	"github.com/Avik-creator/queryguard/pkg/policy"
	"github.com/Avik-creator/queryguard/pkg/proxy"
	"github.com/Avik-creator/queryguard/pkg/session"
	"github.com/Avik-creator/queryguard/pkg/sqlparse"
)

func TestRequireClientTLSNeedsCertificate(t *testing.T) {
	if _, err := loadCertificates("", "", true); err == nil || !strings.Contains(err.Error(), "-require-client-tls") {
		t.Fatalf("got %v; want an error naming -require-client-tls", err)
	}
}

func TestUpstreamTLSDisable(t *testing.T) {
	cfg, err := upstreamTLS("disable", "", "db:5432")
	if err != nil || cfg != nil {
		t.Fatalf("got %v, %v; want nil, nil", cfg, err)
	}
}

func TestUpstreamTLSRequireSkipsVerification(t *testing.T) {
	cfg, err := upstreamTLS("require", "", "db:5432")
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.InsecureSkipVerify {
		t.Error("require verified the certificate; want encryption only, like libpq")
	}
}

func TestUpstreamTLSVerifyFullChecksHostName(t *testing.T) {
	cfg, err := upstreamTLS("verify-full", "", "db.internal:5432")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.InsecureSkipVerify || cfg.ServerName != "db.internal" || cfg.RootCAs != nil {
		t.Errorf("got skip=%v name=%q roots=%v; want verification of db.internal against system roots",
			cfg.InsecureSkipVerify, cfg.ServerName, cfg.RootCAs)
	}
}

func TestUpstreamTLSVerifyFullUsesCAFile(t *testing.T) {
	cert, _ := testcert.Pair(t)
	caFile := filepath.Join(t.TempDir(), "ca.crt")
	writeFile(t, caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]}))

	cfg, err := upstreamTLS("verify-full", caFile, "localhost:5432")
	if err != nil {
		t.Fatal(err)
	}

	want := x509.NewCertPool()
	want.AddCert(cert.Leaf)
	if !cfg.RootCAs.Equal(want) {
		t.Error("RootCAs does not hold exactly the CA file's certificate")
	}
}

func TestUpstreamTLSRejects(t *testing.T) {
	notPEM := filepath.Join(t.TempDir(), "ca.crt")
	writeFile(t, notPEM, []byte("not a certificate"))

	for name, tc := range map[string]struct{ mode, ca, addr string }{
		"unknown mode":         {"prefer", "", "db:5432"},
		"CA without verify":    {"require", notPEM, "db:5432"},
		"missing CA file":      {"verify-full", filepath.Join(t.TempDir(), "missing.crt"), "db:5432"},
		"CA file without PEM":  {"verify-full", notPEM, "db:5432"},
		"address without port": {"verify-full", "", "db"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := upstreamTLS(tc.mode, tc.ca, tc.addr); err == nil {
				t.Fatal("got nil error; want one")
			}
		})
	}
}

func TestLoadPolicy(t *testing.T) {
	// Without a config the policy checks nothing, but the kill switch still has a checker to act through.
	if p, err := loadPolicy(""); p == nil || err != nil || p.NeedsCatalog() {
		t.Errorf("no -config gave %v, %v; want an empty policy", p, err)
	} else if g := p.DDLGuard(); g.Mode != "off" {
		t.Errorf("no -config guards DDL in mode %q; want off, as no config means no checks", g.Mode)
	}

	good := filepath.Join(t.TempDir(), "good.json")
	writeFile(t, good, []byte(`{"rules": [{"check": "require_where"}]}`))
	if p, err := loadPolicy(good); p == nil || err != nil {
		t.Errorf("valid config gave %v, %v; want a policy", p, err)
	}

	bad := filepath.Join(t.TempDir(), "bad.json")
	writeFile(t, bad, []byte(`{"rules": [{"check": "nope"}]}`))
	if _, err := loadPolicy(bad); err == nil {
		t.Error("invalid config gave no error")
	}
}

func TestNewCatalog(t *testing.T) {
	scans, err := policy.Parse([]byte(`{"rules": [{"check": "max_scan_rows", "rows": 1000}]}`))
	if err != nil {
		t.Fatal(err)
	}
	if c, err := newCatalog("", nil, nil); c != nil || err != nil {
		t.Errorf("no -catalog-dsn gave %v, %v; want nil, nil", c, err)
	}
	if _, err := newCatalog("", scans, nil); err == nil || !strings.Contains(err.Error(), "-catalog-dsn") {
		t.Errorf("max_scan_rows without -catalog-dsn gave %v; want an error naming the flag", err)
	}
	if _, err := newCatalog("host=db port=notanumber", scans, nil); err == nil {
		t.Error("an invalid -catalog-dsn gave no error")
	}
	if c, err := newCatalog("host=db user=qg_monitor", scans, nil); c == nil || err != nil || c.DSN != "host=db user=qg_monitor" {
		t.Errorf("valid -catalog-dsn gave %+v, %v", c, err)
	}
}

func TestNewMonitor(t *testing.T) {
	s := &proxy.Server{}
	if m := newMonitor(nil, s, nil); m != nil {
		t.Errorf("no -catalog-dsn gave monitor %v; want none", m)
	}
	m, ok := newMonitor(&plan.Catalog{DSN: "host=db user=qg_monitor"}, s, nil).(*plan.Monitor)
	if !ok || m.DSN != "host=db user=qg_monitor" {
		t.Fatalf("monitor %+v; want one reading over -catalog-dsn", m)
	}
	if got := m.Watch(); got != nil {
		t.Errorf("watched %v with no policy; want nothing", got)
	}
	p, _ := policy.Parse([]byte(`{"mvcc_horizon": {"max_age": "1m", "watch": ["public.jobs"]}}`))
	s.SetPolicy(p)
	if got := m.Watch(); len(got) != 1 || got[0] != (plan.Table{Schema: "public", Name: "jobs"}) {
		t.Errorf("watched %v; want the policy's public.jobs", got)
	}
}

func TestNewFleet(t *testing.T) {
	if f, err := newFleet("", "", "127.0.0.1:6543", 0); f != nil || err != nil {
		t.Errorf("no -state-dsn gave %v, %v; want no fleet", f, err)
	}
	if _, err := newFleet("host=db port=notanumber", "", "127.0.0.1:6543", 0); err == nil {
		t.Error("an invalid -state-dsn gave no error")
	}
	// Peers can't send cancel requests to an address that names every interface.
	if _, err := newFleet("host=db dbname=queryguard_state", "", "0.0.0.0:6543", 0); err == nil || !strings.Contains(err.Error(), "-advertise-addr") {
		t.Errorf("listening on every interface without -advertise-addr gave %v; want an error naming the flag", err)
	}
	f, err := newFleet("host=db dbname=queryguard_state", "", "10.0.0.7:6543", 3)
	if err != nil || f.Addr != "10.0.0.7:6543" || f.MaxInstances != 3 {
		t.Errorf("fleet %+v, %v; want one advertising the listen address, of at most 3", f, err)
	}
	if f, err := newFleet("host=db dbname=queryguard_state", "qg-1.internal:6543", ":6543", 0); err != nil || f.Addr != "qg-1.internal:6543" {
		t.Errorf("fleet %+v, %v; want one advertising -advertise-addr", f, err)
	}
}

func TestReloadKeepsPolicyInForceOnBadConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "queryguard.json")
	first, _ := policy.Parse([]byte(`{}`))
	s := &proxy.Server{}
	s.SetPolicy(first)

	for config, wantErr := range map[string]string{
		`{"rules": [{"check": "nope"}]}`:                      "nope",
		`{"rules": [{"check": "max_scan_rows", "rows": 10}]}`: "-catalog-dsn",
	} {
		writeFile(t, path, []byte(config))
		if err := reload(s, path, nil); err == nil || !strings.Contains(err.Error(), wantErr) {
			t.Errorf("reload of %s = %v; want an error mentioning %q", config, err, wantErr)
		}
		if s.ActivePolicy() != first {
			t.Errorf("a bad config replaced the policy in force: %s", config)
		}
	}

	writeFile(t, path, []byte(`{"rules": [{"check": "require_where"}]}`))
	if err := reload(s, path, nil); err != nil || s.ActivePolicy() == first {
		t.Errorf("reload of a good config = %v, policy replaced = %v", err, s.ActivePolicy() != first)
	}
}

func writeFile(t *testing.T, name string, data []byte) {
	t.Helper()
	if err := os.WriteFile(name, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestAllowlistFileIsLoadedAndSaved(t *testing.T) {
	path := filepath.Join(t.TempDir(), "allowlist.json")
	var list policy.Allowlist
	if err := loadAllowlist(&list, path); err != nil {
		t.Fatalf("a missing file gave %v; want an empty allowlist", err)
	}
	writeFile(t, path, []byte(`{"agent": {"abc": "select $1"}}`))
	if err := loadAllowlist(&list, path); err != nil {
		t.Fatal(err)
	}
	if l := list.List(); len(l) != 1 || l[0].Role != "agent" {
		t.Fatalf("loaded %+v; want agent's statement", l)
	}

	out := filepath.Join(t.TempDir(), "saved.json")
	if err := saveAllowlist(&list, out); err != nil {
		t.Fatal(err)
	}
	var again policy.Allowlist
	if err := loadAllowlist(&again, out); err != nil || len(again.List()) != 1 {
		t.Errorf("saved and loaded %+v, %v; want the one statement", again.List(), err)
	}
}

func TestAdminCLIPrintsAnAlignedTable(t *testing.T) {
	var out strings.Builder
	printTable(&out, []string{"kind", "name"}, [][]string{{"tenant", "acme"}, {"statement", "ab12"}})
	want := "kind       name\ntenant     acme\nstatement  ab12\n"
	if out.String() != want {
		t.Errorf("printed %q; want %q", out.String(), want)
	}
}

func TestSimulateSkipsALineCutShortByACrash(t *testing.T) {
	dir := t.TempDir()
	traffic := filepath.Join(dir, "traffic.jsonl")
	rec := `{"at":"2026-10-05T12:00:00Z","database":"shop","role":"app","tenant":"app","query":"select $1"}` + "\n"
	writeFile(t, traffic, []byte(rec+`{"at":"2026-10-05T12:00:01Z","data`+"\n"+rec+rec))
	config := filepath.Join(dir, "new.json")
	writeFile(t, config, []byte(`{}`))
	var out, errs strings.Builder

	if code := simulateCLI([]string{"-config", config, "-traffic", traffic}, &out, &errs); code != 0 {
		t.Fatalf("exit %d: %s", code, errs.String())
	}
	if !strings.Contains(out.String(), "3 statements") || !strings.Contains(errs.String(), "skipped 1") {
		t.Errorf("printed %q and %q; want the 3 whole records replayed and the bad line reported", out.String(), errs.String())
	}
}

func TestSimulateChecksTheLearnedAllowlist(t *testing.T) {
	dir := t.TempDir()
	traffic := filepath.Join(dir, "traffic.jsonl")
	writeFile(t, traffic, []byte(`{"at":"2026-10-05T12:00:00Z","database":"shop","role":"agent","tenant":"agent","query":"select $1"}`+"\n"+
		`{"at":"2026-10-05T12:00:01Z","database":"shop","role":"agent","tenant":"agent","query":"delete from orders"}`+"\n"))
	list := filepath.Join(dir, "allowlist.json")
	writeFile(t, list, []byte(`{"agent": {"`+sqlparse.Fingerprint("select $1")+`": "select $1"}}`))
	config := filepath.Join(dir, "new.json")
	writeFile(t, config, []byte(`{"allowlist": {"mode": "enforce", "roles": ["agent"]}}`))
	var out, errs strings.Builder

	if code := simulateCLI([]string{"-config", config, "-traffic", traffic, "-allowlist", list}, &out, &errs); code != 0 {
		t.Fatalf("exit %d: %s", code, errs.String())
	}
	if !strings.Contains(out.String(), "allowlist") || !strings.Contains(out.String(), "newly rejected: 1") {
		t.Errorf("printed %q; want the delete refused by the allowlist", out.String())
	}
}

func TestSimulateFailsWithoutTraffic(t *testing.T) {
	config := filepath.Join(t.TempDir(), "new.json")
	writeFile(t, config, []byte(`{}`))
	var out, errs strings.Builder
	if code := simulateCLI([]string{"-config", config, "-traffic", filepath.Join(t.TempDir(), "nope.jsonl")}, &out, &errs); code != 1 {
		t.Errorf("exit %d with no traffic file; want 1", code)
	}
}

func TestSimulateReadsBothTrafficFilesAndPrintsWhatChanges(t *testing.T) {
	dir := t.TempDir()
	traffic := filepath.Join(dir, "traffic.jsonl")
	writeFile(t, traffic+".1", []byte(`{"at":"2026-10-04T12:00:00Z","database":"shop","role":"app","tenant":"app","query":"drop table orders"}`+"\n"))
	writeFile(t, traffic, []byte(`{"at":"2026-10-05T12:00:00Z","database":"shop","role":"app","tenant":"app","query":"select $1"}`+"\n"))
	config := filepath.Join(dir, "new.json")
	writeFile(t, config, []byte(`{"rules": [{"check": "deny_ddl"}]}`))
	var out, errs strings.Builder

	if code := simulateCLI([]string{"-config", config, "-traffic", traffic}, &out, &errs); code != 0 {
		t.Fatalf("exit %d: %s", code, errs.String())
	}

	for _, want := range []string{"2 statements", "deny_ddl", "drop table orders", "newly rejected: 1"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("printed %q; want %q", out.String(), want)
		}
	}
}

func TestAFailedAllowlistSaveIsTriedAgain(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var list policy.Allowlist
		p, err := policy.Parse([]byte(`{"allowlist": {"mode": "learn"}}`))
		if err != nil {
			t.Fatal(err)
		}
		c := p.Checker("agent", slog.New(slog.DiscardHandler))
		c.Env = policy.Env{Database: "shop", Allowlist: &list}
		c.Check("select 1", session.Settings{StandardConformingStrings: "on", ClientEncoding: "UTF8"})
		dir := filepath.Join(t.TempDir(), "later")
		path := filepath.Join(dir, "allowlist.json")
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		go saveAllowlistEvery(ctx, &list, path, slog.New(slog.DiscardHandler))

		// Its directory isn't there yet, so the first save fails.
		time.Sleep(allowlistSaveInterval + time.Second)
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		time.Sleep(allowlistSaveInterval)
		synctest.Wait()

		if _, err := os.Stat(path); err != nil {
			t.Errorf("allowlist not saved once it could be: %v", err)
		}
	})
}

func TestTLSWarningsNameEachUnverifiedConnection(t *testing.T) {
	for _, tc := range []struct {
		name string
		opts options
		want []string
	}{
		{"all verified", options{upstreamSSL: "verify-full", catalogDSN: "host=db sslmode=verify-full", stateDSN: "host=db sslmode=verify-full"}, nil},
		{"require upstream", options{upstreamSSL: "require"}, []string{"-upstream-sslmode=require"}},
		{"catalog without sslmode", options{upstreamSSL: "disable", catalogDSN: "host=db user=monitor"}, []string{"-catalog-dsn"}},
		{"state with require", options{upstreamSSL: "disable", stateDSN: "postgres://qg@db/qg?sslmode=require"}, []string{"-state-dsn"}},
		{"unix socket", options{upstreamSSL: "disable", catalogDSN: "host=/var/run/postgresql user=monitor"}, nil},
	} {
		var got []string
		for _, w := range tlsWarnings(tc.opts) {
			got = append(got, strings.Fields(w)[0])
		}
		if !slices.Equal(got, tc.want) {
			t.Errorf("%s: warnings start %q; want %q", tc.name, got, tc.want)
		}
	}
}

func TestHangupDuringStartupWaitsForTheHandler(t *testing.T) {
	// logrotate's postrotate can signal a process still loading its config.
	hup := catchHangups()
	if err := syscall.Kill(os.Getpid(), syscall.SIGHUP); err != nil {
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond)

	reloaded := make(chan struct{}, 1)
	stop := onHangup(hup, slog.New(slog.DiscardHandler), func() { reloaded <- struct{}{} })
	defer stop()
	select {
	case <-reloaded:
	case <-time.After(5 * time.Second):
		t.Fatal("the SIGHUP sent during startup never reached the handler")
	}
}

func TestHangupWithoutConfigDoesNotStopTheProcess(t *testing.T) {
	reloaded := make(chan struct{}, 1)
	stop := onHangup(catchHangups(), slog.New(slog.DiscardHandler), func() { reloaded <- struct{}{} })
	defer stop()
	if err := syscall.Kill(os.Getpid(), syscall.SIGHUP); err != nil {
		t.Fatal(err)
	}
	select {
	case <-reloaded:
	case <-time.After(5 * time.Second):
		t.Fatal("SIGHUP never reached the handler")
	}
}

func TestCertificateReloadKeepsTheOldOneOnError(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile := filepath.Join(dir, "server.crt"), filepath.Join(dir, "server.key")
	writePair := func(cert tls.Certificate) {
		key, err := x509.MarshalPKCS8PrivateKey(cert.PrivateKey)
		if err != nil {
			t.Fatal(err)
		}
		writeFile(t, certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]}))
		writeFile(t, keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key}))
	}
	first, _ := testcert.Pair(t)
	writePair(first)
	certs, err := loadCertificates(certFile, keyFile, false)
	if err != nil {
		t.Fatal(err)
	}
	cfg := certs.tlsConfig()
	offered := func() []byte {
		c, err := cfg.GetCertificate(&tls.ClientHelloInfo{})
		if err != nil {
			t.Fatal(err)
		}
		return c.Certificate[0]
	}

	second, _ := testcert.Pair(t)
	writePair(second)
	if err := certs.reload(); err != nil || !bytes.Equal(offered(), second.Certificate[0]) {
		t.Fatalf("reload = %v; want the new certificate offered", err)
	}
	writeFile(t, keyFile, []byte("not a key"))
	if err := certs.reload(); err == nil || !bytes.Equal(offered(), second.Certificate[0]) {
		t.Errorf("reload of a bad key = %v; want an error and the certificate in force kept", err)
	}
}

func TestDecisionLogGetsOnlyRuleRecordsAndMetricsCountThem(t *testing.T) {
	path := filepath.Join(t.TempDir(), "decisions.jsonl")
	var console bytes.Buffer
	log, metrics, decisions, err := newLogger(options{decisionLog: path, metricsListen: "127.0.0.1:0"}, &console)
	if err != nil {
		t.Fatal(err)
	}
	defer decisions.Close()

	log.Info("queryguard started")
	log.Warn("rejected statement", "rule", "budget", "tenant", "acme")

	got, _ := os.ReadFile(path)
	if lines := strings.Count(string(got), "\n"); lines != 1 || !strings.Contains(string(got), `"rule":"budget"`) {
		t.Errorf("decision log holds %q; want the one rejection as JSON", got)
	}
	if !strings.Contains(console.String(), "queryguard started") {
		t.Errorf("console lost the other line: %q", console.String())
	}
	rec := httptest.NewRecorder()
	metrics.ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil))
	for _, want := range []string{`queryguard_decisions_total{rule="budget",message="rejected statement"} 1`, `queryguard_build_info{version="dev"} 1`} {
		if !strings.Contains(rec.Body.String(), want) {
			t.Errorf("metrics lack %s", want)
		}
	}
}

func TestNoTelemetryFlagsKeepJustTheConsole(t *testing.T) {
	log, metrics, decisions, err := newLogger(options{}, io.Discard)
	if err != nil || log == nil || metrics != nil || decisions != nil {
		t.Errorf("got %v, %v, %v, %v; want a console logger only", log, metrics, decisions, err)
	}
}

func TestTestCLIChecksACorpusAgainstAConfig(t *testing.T) {
	dir := t.TempDir()
	config, corpus := filepath.Join(dir, "agent.json"), filepath.Join(dir, "bypass.sql")
	writeFile(t, config, []byte(`{"rules": [{"check": "read_only"}, {"check": "deny_functions"}]}`))
	writeFile(t, corpus, []byte(`-- Statements an agent might try.

-- reject read_only
COMMIT;
DROP TABLE orders;

-- reject
select pg_terminate_backend(42)

-- allow
select * from orders -- reject is only a marker at the start of a line
where id = 1;

-- allow
insert into orders values (1);
`))
	var stdout, stderr bytes.Buffer
	code := testCLI([]string{"-config", config, corpus}, &stdout, &stderr)

	if code != 1 {
		t.Errorf("exit code %d; want 1 for the insert that was let through", code)
	}
	out := stdout.String()
	if !strings.Contains(out, "bypass.sql:15: want allow, got reject (read_only): insert into orders values (1);") {
		t.Errorf("output doesn't name the failing case:\n%s", out)
	}
	if !strings.Contains(out, "3 passed, 1 failed") {
		t.Errorf("output lacks the summary:\n%s", out)
	}
}

func TestTestCLIChecksTheRuleNamed(t *testing.T) {
	dir := t.TempDir()
	config, corpus := filepath.Join(dir, "agent.json"), filepath.Join(dir, "cases.sql")
	writeFile(t, config, []byte(`{"rules": [{"check": "deny_ddl"}, {"check": "read_only"}]}`))
	writeFile(t, corpus, []byte("-- reject read_only\ndrop table orders;\n"))
	var stdout, stderr bytes.Buffer
	if code := testCLI([]string{"-config", config, corpus}, &stdout, &stderr); code != 1 || !strings.Contains(stdout.String(), "got reject (deny_ddl)") {
		t.Errorf("exit %d, output %q; want a failure naming deny_ddl", code, stdout.String())
	}
}

func TestTestCLIWithoutACorpusOnlyValidatesTheConfig(t *testing.T) {
	config := filepath.Join(t.TempDir(), "bad.json")
	writeFile(t, config, []byte(`{"rules": [{"check": "nope"}]}`))
	var stdout, stderr bytes.Buffer
	if code := testCLI([]string{"-config", config}, &stdout, &stderr); code != 1 || !strings.Contains(stderr.String(), "nope") {
		t.Errorf("exit %d, stderr %q; want the config's error", code, stderr.String())
	}
	writeFile(t, config, []byte(`{"rules": [{"check": "max_cost", "cost": 1000}]}`))
	stdout.Reset()
	if code := testCLI([]string{"-config", config}, &stdout, &stderr); code != 0 || !strings.Contains(stdout.String(), "config is valid") {
		t.Errorf("exit %d, stdout %q; want the config found valid", code, stdout.String())
	}
}

func TestShippedAIAgentPresetRejectsItsBypassCorpus(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := testCLI([]string{"-config", "../../presets/ai-agent.json", "../../presets/ai-agent-bypass.sql"}, &stdout, &stderr)
	if code != 0 {
		t.Errorf("exit %d:\n%s%s", code, stdout.String(), stderr.String())
	}
}
