// Package telemetry serves Prometheus metrics and keeps the decision log, a JSON line for each rule that acted.
package telemetry

import (
	"bufio"
	"cmp"
	"context"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"math"
	"net/http"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
)

// maxSeries is the most label sets one metric keeps; the rest are counted under otherLabel, so tenant names can't grow it without end.
const maxSeries = 1000

// otherLabel is the label value of every label set past maxSeries.
const otherLabel = "_other"

// Registry holds metrics and writes them in Prometheus's text format; the zero value is ready to use.
type Registry struct {
	mu      sync.Mutex
	metrics []metric
	byName  map[string]metric
}

// metric is one metric family.
type metric interface {
	write(w *bufio.Writer)
}

// register adds m under name, or returns the metric already there.
func (r *Registry) register(name string, m metric) metric {
	r.mu.Lock()
	defer r.mu.Unlock()
	if old, ok := r.byName[name]; ok {
		return old
	}
	if r.byName == nil {
		r.byName = map[string]metric{}
	}
	r.byName[name] = m
	r.metrics = append(r.metrics, m)
	return m
}

// ServeHTTP writes every metric, in the order they were made.
func (r *Registry) ServeHTTP(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	r.mu.Lock()
	metrics := slices.Clone(r.metrics)
	r.mu.Unlock()
	bw := bufio.NewWriter(w)
	for _, m := range metrics {
		m.write(bw)
	}
	bw.Flush()
}

// family is what every kind of metric shares: its name, help text and label names.
type family struct {
	name, help, kind string
	labels           []string
}

func (f family) header(w *bufio.Writer) {
	fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s %s\n", f.name, helpEscaper.Replace(f.help), f.name, f.kind)
}

// Prometheus's text format escapes these in label values, and all but the quote in help text.
var (
	labelEscaper = strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`)
	helpEscaper  = strings.NewReplacer(`\`, `\\`, "\n", `\n`)
)

// sample writes one line: the family's name with suffix, its labels with values and any extra pair, and v.
func (f family) sample(w *bufio.Writer, suffix string, values []string, extra []string, v float64) {
	w.WriteString(f.name + suffix)
	names := append(slices.Clone(f.labels), extra[:len(extra)/2]...)
	all := append(slices.Clone(values), extra[len(extra)/2:]...)
	if len(names) > 0 {
		w.WriteByte('{')
		for i, n := range names {
			if i > 0 {
				w.WriteByte(',')
			}
			fmt.Fprintf(w, "%s=\"%s\"", n, labelEscaper.Replace(all[i]))
		}
		w.WriteByte('}')
	}
	w.WriteString(" " + formatFloat(v) + "\n")
}

// formatFloat writes v as Prometheus reads it.
func formatFloat(v float64) string {
	if math.IsInf(v, 1) {
		return "+Inf"
	}
	return strconv.FormatFloat(v, 'g', -1, 64)
}

// key joins label values into a map key.
func key(values []string) string { return strings.Join(values, "\xff") }

// Counter is a metric that only goes up, one value for each label set.
type Counter struct {
	family
	mu     sync.Mutex
	series map[string]*counterSeries
}

type counterSeries struct {
	values []string
	v      float64
}

// Counter returns the counter called name with the given label names, making it on first use.
func (r *Registry) Counter(name, help string, labels ...string) *Counter {
	return r.register(name, &Counter{family: family{name, help, "counter", labels}, series: map[string]*counterSeries{}}).(*Counter)
}

// Inc adds one for the label values.
func (c *Counter) Inc(values ...string) { c.Add(1, values...) }

// Add adds v for the label values.
func (c *Counter) Add(v float64, values ...string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	values = c.fit(values)
	s, ok := c.series[key(values)]
	if !ok {
		if len(c.series) >= maxSeries {
			values = other(len(values))
			s, ok = c.series[key(values)]
		}
		if !ok {
			s = &counterSeries{values: slices.Clone(values)}
			c.series[key(values)] = s
		}
	}
	s.v += v
}

// fit pads or cuts values to one for each label name.
func (f family) fit(values []string) []string {
	if len(values) == len(f.labels) {
		return values
	}
	out := make([]string, len(f.labels))
	copy(out, values)
	return out
}

// other is the label set every label set past maxSeries is counted under.
func other(n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = otherLabel
	}
	return out
}

// value returns the count for the label values.
func (c *Counter) value(values ...string) float64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	if s, ok := c.series[key(c.fit(values))]; ok {
		return s.v
	}
	return 0
}

func (c *Counter) write(w *bufio.Writer) {
	c.header(w)
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, k := range slices.Sorted(maps.Keys(c.series)) {
		s := c.series[k]
		c.sample(w, "", s.values, nil, s.v)
	}
}

// Histogram counts observations into buckets, one set for each label set.
type Histogram struct {
	family
	buckets []float64
	mu      sync.Mutex
	series  map[string]*histogramSeries
}

type histogramSeries struct {
	values []string
	counts []uint64 // by bucket, not cumulative; the last is past every bound
	sum    float64
	count  uint64
}

// Histogram returns the histogram called name with upper bounds buckets, in increasing order, making it on first use.
func (r *Registry) Histogram(name, help string, buckets []float64, labels ...string) *Histogram {
	h := &Histogram{family: family{name, help, "histogram", labels}, buckets: buckets, series: map[string]*histogramSeries{}}
	return r.register(name, h).(*Histogram)
}

// Observe counts v for the label values.
func (h *Histogram) Observe(v float64, values ...string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	values = h.fit(values)
	s, ok := h.series[key(values)]
	if !ok {
		if len(h.series) >= maxSeries {
			values = other(len(values))
			s, ok = h.series[key(values)]
		}
		if !ok {
			s = &histogramSeries{values: slices.Clone(values), counts: make([]uint64, len(h.buckets)+1)}
			h.series[key(values)] = s
		}
	}
	i, _ := slices.BinarySearch(h.buckets, v)
	s.counts[i]++
	s.sum += v
	s.count++
}

func (h *Histogram) write(w *bufio.Writer) {
	h.header(w)
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, k := range slices.Sorted(maps.Keys(h.series)) {
		s := h.series[k]
		var total uint64
		for i, n := range s.counts {
			total += n
			le := math.Inf(1)
			if i < len(h.buckets) {
				le = h.buckets[i]
			}
			h.sample(w, "_bucket", s.values, []string{"le", formatFloat(le)}, float64(total))
		}
		h.sample(w, "_sum", s.values, nil, s.sum)
		h.sample(w, "_count", s.values, nil, float64(s.count))
	}
}

// collected is a metric whose values are read at each scrape.
type collected struct {
	family
	collect func(emit func(v float64, values ...string))
}

// Gauge adds a gauge whose values collect gives at each scrape, by calling emit once for each label set.
func (r *Registry) Gauge(name, help string, collect func(emit func(v float64, values ...string)), labels ...string) {
	r.register(name, &collected{family{name, help, "gauge", labels}, collect})
}

// CounterFunc adds a counter whose values collect gives at each scrape, for counts kept elsewhere.
func (r *Registry) CounterFunc(name, help string, collect func(emit func(v float64, values ...string)), labels ...string) {
	r.register(name, &collected{family{name, help, "counter", labels}, collect})
}

func (c *collected) write(w *bufio.Writer) {
	c.header(w)
	c.collect(func(v float64, values ...string) { c.sample(w, "", c.fit(values), nil, v) })
}

// counter returns the counter called name, or nil.
func (r *Registry) counter(name string) *Counter {
	r.mu.Lock()
	defer r.mu.Unlock()
	c, _ := r.byName[name].(*Counter)
	return c
}

// Decisions is a slog.Handler that passes records on and also counts and logs the decisions among them: records with a rule attribute.
type Decisions struct {
	next, log slog.Handler
	count     *Counter
	rule      string // the rule set by WithAttrs, or ""
}

// NewDecisions returns a handler that passes every record to next, and those with a rule to log as well; r counts them; either may be nil.
func NewDecisions(next slog.Handler, r *Registry, log slog.Handler) *Decisions {
	d := &Decisions{next: next, log: log}
	if r != nil {
		d.count = r.Counter("queryguard_decisions_total", "Rules that acted, such as a rejected statement, by rule and log message.", "rule", "message")
	}
	return d
}

func (d *Decisions) Enabled(ctx context.Context, level slog.Level) bool {
	return d.next.Enabled(ctx, level) || d.count != nil || d.log != nil && d.log.Enabled(ctx, level)
}

func (d *Decisions) Handle(ctx context.Context, rec slog.Record) error {
	rule := d.rule
	rec.Attrs(func(a slog.Attr) bool {
		if a.Key == "rule" {
			rule = a.Value.String()
			return false
		}
		return true
	})
	var err error
	if d.next.Enabled(ctx, rec.Level) {
		err = d.next.Handle(ctx, rec)
	}
	if rule == "" {
		return err
	}
	if d.count != nil {
		d.count.Inc(rule, rec.Message)
	}
	if d.log != nil && d.log.Enabled(ctx, rec.Level) {
		err = cmp.Or(err, d.log.Handle(ctx, rec.Clone()))
	}
	return err
}

func (d *Decisions) WithAttrs(attrs []slog.Attr) slog.Handler {
	n := *d
	n.next = d.next.WithAttrs(attrs)
	if d.log != nil {
		n.log = d.log.WithAttrs(attrs)
	}
	for _, a := range attrs {
		if a.Key == "rule" {
			n.rule = a.Value.String()
		}
	}
	return &n
}

func (d *Decisions) WithGroup(name string) slog.Handler {
	n := *d
	n.next = d.next.WithGroup(name)
	if d.log != nil {
		n.log = d.log.WithGroup(name)
	}
	return &n
}

// File is an append-only log file that Reopen opens again by name, after a log rotator has moved it.
type File struct {
	path string
	mu   sync.Mutex
	f    *os.File
}

// OpenFile opens path for appending, making it if need be.
func OpenFile(path string) (*File, error) {
	f := &File{path: path}
	if err := f.Reopen(); err != nil {
		return nil, err
	}
	return f, nil
}

// Reopen closes the file and opens path again.
func (f *File) Reopen() error {
	nf, err := os.OpenFile(f.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.f != nil {
		f.f.Close()
	}
	f.f = nf
	return nil
}

func (f *File) Write(p []byte) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.f.Write(p)
}

// Close closes the file.
func (f *File) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.f.Close()
}

var _ io.Writer = (*File)(nil)
