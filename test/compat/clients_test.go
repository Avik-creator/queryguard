package compat

import (
	"context"
	"io"
	"net"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// TestClients runs each client's script from clients/ in a container that shares the host's network.
func TestClients(t *testing.T) {
	qg := startProxy(t)
	rules := startRulesProxy(t, io.Discard)
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker not found")
	}
	scripts, err := filepath.Abs("clients")
	if err != nil {
		t.Fatal(err)
	}
	_, port, _ := net.SplitHostPort(qg.addr)
	_, rulesPort, _ := net.SplitHostPort(rules.addr)

	for _, c := range []struct {
		name, image string
		cmd         []string
	}{
		{"psql", "postgres:18", []string{"sh", "/scripts/psql.sh"}},
		{"node-postgres", "node:24-alpine", []string{"sh", "-c", "cd /tmp && npm install --silent --no-audit --no-fund pg@8 && cp /scripts/node.mjs . && node node.mjs"}},
		{"psycopg", "python:3.14-slim", []string{"sh", "-c", "pip install --quiet --root-user-action=ignore --disable-pip-version-check 'psycopg[binary]>=3.2,<4' && python /scripts/psycopg_check.py"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Minute)
			defer cancel()
			args := []string{
				"run", "--rm", "--network", "host",
				"-v", scripts + ":/scripts:ro",
				"-v", filepath.Dir(qg.caFile) + ":/certs:ro",
				"-e", "QG_HOST=127.0.0.1", "-e", "QG_PORT=" + port, "-e", "QG_RULES_PORT=" + rulesPort,
				"-e", "QG_CA=/certs/ca.crt", "-e", "PGPASSWORD=" + password(),
				"--entrypoint", c.cmd[0], c.image,
			}
			out, err := exec.CommandContext(ctx, "docker", append(args, c.cmd[1:]...)...).CombinedOutput()
			t.Logf("%s output:\n%s", c.name, out)
			if err != nil {
				t.Fatalf("%s: %v", c.name, err)
			}
		})
	}
}
