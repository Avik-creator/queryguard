package compat

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Avik-creator/queryguard/pkg/fleet"
	"github.com/Avik-creator/queryguard/pkg/proxy"
)

func TestPostgresStoreSharesCapacity(t *testing.T) {
	store := &fleet.Postgres{DSN: stateDSN(t)}
	resource := fmt.Sprintf("rate:test_%d", time.Now().UnixNano())
	want := func(demand float64) func() map[string]fleet.Want {
		return func() map[string]fleet.Want { return map[string]fleet.Want{resource: {Capacity: 100, Demand: demand}} }
	}
	a := &fleet.Fleet{Store: store, Addr: "10.0.0.1:6543", Interval: 100 * time.Millisecond}
	b := &fleet.Fleet{Store: &fleet.Postgres{DSN: stateDSN(t)}, Addr: "10.0.0.2:6543", Interval: 100 * time.Millisecond}
	ctx, stop := context.WithCancel(t.Context())
	defer stop()
	go a.Run(ctx, want(30), nil)
	go b.Run(ctx, want(10), nil)

	// 60 spare units go half to each.
	waitFor(t, 5*time.Second, func() bool {
		return math.Abs(a.Share(resource)-60) < 1e-6 && math.Abs(b.Share(resource)-40) < 1e-6
	})
	if a.ID() == 0 || b.ID() == 0 || a.ID() == b.ID() {
		t.Errorf("ids %d and %d; want two distinct ones", a.ID(), b.ID())
	}
	if addr, ok := a.Peer(b.ID()); !ok || addr != "10.0.0.2:6543" {
		t.Errorf("a's peer %d is %q, %v; want b's address", b.ID(), addr, ok)
	}

	stop()
	if err := b.Release(context.Background()); err != nil {
		t.Fatal(err)
	}
	ctx, stop = context.WithCancel(t.Context())
	defer stop()
	go a.Run(ctx, want(30), nil)
	waitFor(t, 5*time.Second, func() bool { return math.Abs(a.Share(resource)-100) < 1e-6 })
	if err := a.Release(context.Background()); err != nil {
		t.Fatal(err)
	}
}

// stateDSN connects to a database set aside for QueryGuard's fleet state on QG_TEST_UPSTREAM, making it if it is missing.
func stateDSN(t testing.TB) string {
	t.Helper()
	dsn := catalogDSN(t)
	admin := connectTo(t, os.Getenv("QG_TEST_UPSTREAM"), "sslmode=disable")
	var exists bool
	if err := admin.QueryRow(t.Context(), "select exists (select from pg_database where datname = 'queryguard_state')").Scan(&exists); err != nil {
		t.Fatal(err)
	}
	if !exists {
		mustExec(t, admin, "create database queryguard_state")
	}
	return dsn + " dbname=queryguard_state"
}

func TestFleetHoldsATenantToOneRate(t *testing.T) {
	if os.Getenv("QG_TEST_UPSTREAM") == "" {
		t.Skip("set QG_TEST_UPSTREAM to a Postgres host:port")
	}
	// Each statement costs its min_charge of 100, so the fleet admits 10 a second however the load is spread.
	tenant := fmt.Sprintf("fleet_%d", time.Now().UnixNano())
	config := `{"trusted_roles": ["postgres"], "tenants": {"` + tenant + `": {"budget": {"rate": 1000, "burst": 1000, "min_charge": 100, "when_over": "reject"}}}}`
	lb := startFleet(t, 3, config)
	var admitted atomic.Int64
	ctx, stop := context.WithCancel(t.Context())
	var clients sync.WaitGroup
	for range 6 {
		conn := connectTo(t, lb, "sslmode=disable")
		clients.Go(func() {
			for ctx.Err() == nil {
				if _, err := conn.Exec(ctx, "select 1 /*tenant='"+tenant+"'*/"); err == nil {
					admitted.Add(1)
				} else if sqlState(err) == "53000" {
					time.Sleep(5 * time.Millisecond)
				}
			}
		})
	}
	// The instances settle on their shares, and spend what they saved up, before counting starts.
	time.Sleep(3 * time.Second)
	admitted.Store(0)
	const window = 20 * time.Second
	time.Sleep(window)
	n := admitted.Load()
	stop()
	clients.Wait()

	if want := 10 * window.Seconds(); math.Abs(float64(n)-want) > 0.1*want {
		t.Errorf("the fleet admitted %d statements in %v; want %v within 10%%", n, window, want)
	}
}

func TestCancelThroughAnotherInstance(t *testing.T) {
	if os.Getenv("QG_TEST_UPSTREAM") == "" {
		t.Skip("set QG_TEST_UPSTREAM to a Postgres host:port")
	}
	lb := startFleet(t, 3, `{}`)
	conn := connectTo(t, lb, "sslmode=disable")
	// The instances need a lease to know each other.
	time.Sleep(time.Second)

	// The cancel request goes out on a new connection, which the load balancer gives the next instance.
	time.AfterFunc(300*time.Millisecond, func() { conn.PgConn().CancelRequest(t.Context()) })
	start := time.Now()
	sleepCtx, stop := context.WithTimeout(t.Context(), 10*time.Second)
	defer stop()
	_, err := conn.Exec(sleepCtx, "select pg_sleep(30)")

	if sqlState(err) != "57014" || time.Since(start) > 5*time.Second {
		t.Errorf("pg_sleep(30) ended with %v after %v; want SQLSTATE 57014 within a few seconds", err, time.Since(start))
	}
	expectSelectOne(t, conn)
}

func TestFleetNeverAdmitsMoreThanTheTotalThroughStoreFaults(t *testing.T) {
	if os.Getenv("QG_TEST_UPSTREAM") == "" {
		t.Skip("set QG_TEST_UPSTREAM to a Postgres host:port")
	}
	store := toxicStore(t)
	tenant := fmt.Sprintf("fleet_%d", time.Now().UnixNano())
	config := `{"trusted_roles": ["postgres"], "tenants": {"` + tenant + `": {"budget": {"rate": 1000, "burst": 1000, "min_charge": 100, "when_over": "reject"}}}}`
	// Short leases, so a lost store shows within seconds.
	lb := startFleetWith(t, 3, config, store.dsn, func(f *fleet.Fleet) { f.TTL, f.DeadAfter, f.MaxInstances = 2*time.Second, 6*time.Second, 3 })
	var admitted atomic.Int64
	ctx, stop := context.WithCancel(t.Context())
	var clients sync.WaitGroup
	defer clients.Wait()
	defer stop()
	for range 6 {
		conn := connectTo(t, lb, "sslmode=disable")
		clients.Go(func() {
			for ctx.Err() == nil {
				if _, err := conn.Exec(ctx, "select 1 /*tenant='"+tenant+"'*/"); err == nil {
					admitted.Add(1)
				} else if sqlState(err) == "53000" {
					time.Sleep(5 * time.Millisecond)
				}
			}
		})
	}
	time.Sleep(3 * time.Second)
	// phase counts what the fleet admits over d; it may never pass the rate of 10 a second, burst aside.
	phase := func(name string, d time.Duration) int64 {
		admitted.Store(0)
		time.Sleep(d)
		n := admitted.Load()
		if limit := 1.1*10*d.Seconds() + 10; float64(n) > limit {
			t.Errorf("%s: admitted %d in %v; want at most %.0f", name, n, d, limit)
		}
		t.Logf("%s: admitted %d in %v", name, n, d)
		return n
	}

	if n := phase("store up", 4*time.Second); n < 30 {
		t.Errorf("store up: admitted only %d in 4s; want about 40", n)
	}
	// Replies now come after the next renewal is due, so no lease is renewed and each instance falls back.
	store.toxic(t, `{"name": "slow", "type": "latency", "stream": "downstream", "attributes": {"latency": 1500}}`)
	if n := phase("store slow", 4*time.Second); n < 20 {
		t.Errorf("store slow: admitted only %d in 4s; want leases, then fallback shares, to keep statements running", n)
	}
	store.removeToxic(t, "slow")
	store.enable(t, false)
	if n := phase("store down", 3*time.Second); n == 0 {
		t.Error("store down: admitted nothing; want fallback shares to keep statements running until dead_after")
	}
	// Six seconds after their last renewal, at most ten seconds ago, the instances stopped using their fallback shares.
	if n := phase("store down past dead_after", 4*time.Second); n != 0 {
		t.Errorf("store down past dead_after: admitted %d; want none", n)
	}
	store.enable(t, true)
	time.Sleep(time.Second)
	if n := phase("store back", 4*time.Second); n < 30 {
		t.Errorf("store back: admitted only %d in 4s; want about 40", n)
	}
}

// toxic is a Toxiproxy proxy in front of QG_TEST_UPSTREAM's server.
type toxic struct {
	api, name, dsn string
}

// toxicStore makes a Toxiproxy proxy to the state database of QG_TEST_UPSTREAM's server, skipping the test without Toxiproxy.
func toxicStore(t *testing.T) *toxic {
	t.Helper()
	dsn := stateDSN(t)
	_, port, _ := net.SplitHostPort(os.Getenv("QG_TEST_UPSTREAM"))
	x := &toxic{api: "http://127.0.0.1:8474", name: "qg_state_" + port}
	if _, err := http.Get(x.api + "/version"); err != nil {
		t.Skip("Toxiproxy is not running; start it with make up")
	}
	// docker compose names each server pgNN, and the proxy for 54NN listens on 554NN.
	body := fmt.Sprintf(`{"name": %q, "listen": "0.0.0.0:55%s", "upstream": "pg%s:5432"}`, x.name, port[1:], port[2:])
	x.call(t, "DELETE", "/proxies/"+x.name, "", 0)
	x.call(t, "POST", "/proxies", body, http.StatusCreated)
	t.Cleanup(func() { x.call(t, "DELETE", "/proxies/"+x.name, "", 0) })
	x.dsn = strings.Replace(dsn, "port="+port, "port=55"+port[1:], 1)
	return x
}

func (x *toxic) toxic(t *testing.T, body string) {
	x.call(t, "POST", "/proxies/"+x.name+"/toxics", body, http.StatusOK)
}

func (x *toxic) removeToxic(t *testing.T, name string) {
	x.call(t, "DELETE", "/proxies/"+x.name+"/toxics/"+name, "", http.StatusNoContent)
}

func (x *toxic) enable(t *testing.T, on bool) {
	x.call(t, "POST", "/proxies/"+x.name, fmt.Sprintf(`{"enabled": %v}`, on), http.StatusOK)
}

// call sends a request to Toxiproxy's API, failing the test unless the answer has status want; 0 takes any.
func (x *toxic) call(t *testing.T, method, path, body string, want int) {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), method, x.api+path, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if msg, _ := io.ReadAll(resp.Body); want != 0 && resp.StatusCode != want {
		t.Fatalf("%s %s: %s %s", method, path, resp.Status, msg)
	}
}

// startFleet starts n proxies with config sharing a Postgres store, behind a round-robin load balancer whose address it returns.
func startFleet(t *testing.T, n int, config string) string {
	t.Helper()
	return startFleetWith(t, n, config, stateDSN(t), func(*fleet.Fleet) {})
}

// startFleetWith is startFleet with the store at dsn, letting configure change each instance's Fleet.
func startFleetWith(t *testing.T, n int, config, dsn string, configure func(*fleet.Fleet)) string {
	t.Helper()
	var backends []string
	for range n {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		s := &proxy.Server{
			Upstream: proxy.Dialer{Addr: os.Getenv("QG_TEST_UPSTREAM")},
			Policy:   mustPolicy(t, config),
			Fleet:    &fleet.Fleet{Store: &fleet.Postgres{DSN: dsn}, Addr: ln.Addr().String(), Interval: 200 * time.Millisecond},
			Logger:   slog.New(slog.NewTextHandler(t.Output(), nil)),
		}
		configure(s.Fleet)
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() { done <- s.Serve(ctx, ln) }()
		t.Cleanup(func() {
			cancel()
			<-done
		})
		backends = append(backends, ln.Addr().String())
	}
	return startRoundRobin(t, backends)
}

// startRoundRobin forwards each connection to the next of backends in turn, as a TCP load balancer does.
func startRoundRobin(t *testing.T, backends []string) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	var next atomic.Int64
	go func() {
		for {
			client, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer client.Close()
				server, err := net.Dial("tcp", backends[int(next.Add(1)-1)%len(backends)])
				if err != nil {
					return
				}
				defer server.Close()
				go func() {
					io.Copy(server, client)
					server.Close()
				}()
				io.Copy(client, server)
			}()
		}
	}()
	return ln.Addr().String()
}
