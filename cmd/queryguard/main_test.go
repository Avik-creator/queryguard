package main

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Avik-creator/queryguard/internal/testcert"
	"github.com/Avik-creator/queryguard/pkg/plan"
	"github.com/Avik-creator/queryguard/pkg/policy"
	"github.com/Avik-creator/queryguard/pkg/proxy"
)

func TestRequireClientTLSNeedsCertificate(t *testing.T) {
	if _, err := loadTLS("", "", true); err == nil || !strings.Contains(err.Error(), "-require-client-tls") {
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
	if p, err := loadPolicy(""); p != nil || err != nil {
		t.Errorf("no -config gave %v, %v; want nil, nil", p, err)
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
