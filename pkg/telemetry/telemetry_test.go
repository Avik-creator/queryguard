package telemetry

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestRegistryWritesPrometheusText(t *testing.T) {
	var r Registry
	statements := r.Counter("qg_statements_total", "Statements by result.", "tenant", "result")
	statements.Inc("acme", "ok")
	statements.Inc("acme", "ok")
	statements.Add(3, "say \"hi\"\\\n", "error")
	took := r.Histogram("qg_seconds", "Statement time.", []float64{0.1, 1}, "tenant")
	took.Observe(0.0625, "acme")
	took.Observe(0.5, "acme")
	took.Observe(2, "acme")
	r.Gauge("qg_limit", "Fast lane slots.", func(emit func(float64, ...string)) { emit(8) })
	r.CounterFunc("qg_hits_total", "Plan cache hits.", func(emit func(float64, ...string)) { emit(12) })

	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil))

	want := `# HELP qg_statements_total Statements by result.
# TYPE qg_statements_total counter
qg_statements_total{tenant="acme",result="ok"} 2
qg_statements_total{tenant="say \"hi\"\\\n",result="error"} 3
# HELP qg_seconds Statement time.
# TYPE qg_seconds histogram
qg_seconds_bucket{tenant="acme",le="0.1"} 1
qg_seconds_bucket{tenant="acme",le="1"} 2
qg_seconds_bucket{tenant="acme",le="+Inf"} 3
qg_seconds_sum{tenant="acme"} 2.5625
qg_seconds_count{tenant="acme"} 3
# HELP qg_limit Fast lane slots.
# TYPE qg_limit gauge
qg_limit 8
# HELP qg_hits_total Plan cache hits.
# TYPE qg_hits_total counter
qg_hits_total 12
`
	if got := rec.Body.String(); got != want {
		t.Errorf("got\n%s\nwant\n%s", got, want)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/plain; version=0.0.4") {
		t.Errorf("Content-Type %q; want Prometheus's text format", ct)
	}
}

func TestGaugeFoldsLabelSetsPastTheCap(t *testing.T) {
	var r Registry
	r.Gauge("qg_running", "Statements running.", func(emit func(float64, ...string)) {
		for i := range maxSeries + 5 {
			emit(1, strconv.Itoa(i))
		}
	}, "tenant")

	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil))

	if n := strings.Count(rec.Body.String(), "qg_running{"); n != maxSeries+1 {
		t.Errorf("wrote %d series; want %d and one for the rest", n, maxSeries)
	}
	if !strings.Contains(rec.Body.String(), `qg_running{tenant="_other"} 5`) {
		t.Error("the series past the cap aren't added up under _other")
	}
}

func TestStalledScrapeHoldsUpNoObservation(t *testing.T) {
	var r Registry
	took := r.Histogram("qg_seconds", "Statement time.", []float64{0.1, 1}, "tenant")
	for i := range 200 {
		took.Observe(1, strconv.Itoa(i))
	}
	w := &stalledWriter{header: http.Header{}, writing: make(chan struct{}, 1), release: make(chan struct{})}
	defer close(w.release)
	go r.ServeHTTP(w, httptest.NewRequest("GET", "/metrics", nil))
	<-w.writing

	// Every statement observes its time, so a scraper that stops reading mustn't stop them.
	done := make(chan struct{})
	go func() {
		took.Observe(1, "acme")
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Observe waited for a scrape that stopped reading")
	}
}

// stalledWriter is a response whose reader stops reading until release is closed.
type stalledWriter struct {
	header  http.Header
	writing chan struct{} // gets a value once a write is stuck
	release chan struct{}
}

func (w *stalledWriter) Header() http.Header { return w.header }
func (w *stalledWriter) WriteHeader(int)     {}
func (w *stalledWriter) Write(b []byte) (int, error) {
	select {
	case w.writing <- struct{}{}:
	default:
	}
	<-w.release
	return len(b), nil
}

func TestCounterFoldsLabelSetsPastItsCap(t *testing.T) {
	var r Registry
	c := r.Counter("qg_total", "", "tenant")
	for i := range maxSeries + 5 {
		c.Inc(strings.Repeat("t", i+1))
	}
	if got := c.value(otherLabel); got != 5 {
		t.Errorf("label sets past the cap counted %v under %q; want 5", got, otherLabel)
	}
	if n := len(c.series); n != maxSeries+1 {
		t.Errorf("kept %d series; want the cap plus %q", n, otherLabel)
	}
}

func TestDecisionsCountAndLogOnlyRecordsWithARule(t *testing.T) {
	var console, decisions bytes.Buffer
	var r Registry
	log := slog.New(NewDecisions(slog.NewTextHandler(&console, nil), &r, slog.NewJSONHandler(&decisions, nil)))

	log.Info("queryguard started")
	log.Warn("rejected statement", "rule", "budget", "tenant", "acme")
	log.With("client", "10.0.0.1").Warn("would reject statement", "rule", "busy", "tenant", "beta")
	log.With("rule", "ddl_guard").Warn("cancelled DDL waiting on a lock")

	if n := strings.Count(console.String(), "\n"); n != 4 {
		t.Errorf("console got %d lines; want all 4", n)
	}
	var lines []map[string]any
	for line := range strings.Lines(decisions.String()) {
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatal(err)
		}
		lines = append(lines, m)
	}
	if len(lines) != 3 || lines[0]["rule"] != "budget" || lines[1]["client"] != "10.0.0.1" || lines[2]["rule"] != "ddl_guard" {
		t.Fatalf("decision log got %v; want the three records with a rule, with their attributes", lines)
	}
	if got := r.counter("queryguard_decisions_total").value("busy", "would reject statement"); got != 1 {
		t.Errorf("decisions counted %v for busy; want 1", got)
	}
}

func TestFileReopensAfterRotation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "decisions.jsonl")
	f, err := OpenFile(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	f.Write([]byte("first\n"))
	if err := os.Rename(path, path+".1"); err != nil {
		t.Fatal(err)
	}
	if err := f.Reopen(); err != nil {
		t.Fatal(err)
	}
	f.Write([]byte("second\n"))

	if got, _ := os.ReadFile(path); string(got) != "second\n" {
		t.Errorf("new file holds %q; want only the line after the reopen", got)
	}
}
