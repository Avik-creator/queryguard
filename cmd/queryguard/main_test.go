package main

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/Avik-creator/queryguard/internal/testcert"
)

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

func writeFile(t *testing.T, name string, data []byte) {
	t.Helper()
	if err := os.WriteFile(name, data, 0o600); err != nil {
		t.Fatal(err)
	}
}
