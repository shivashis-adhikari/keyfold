// package sim replays access logs through cache policies, once with the
// key the cdn uses today and once with the planned key, and compares them.
package sim

import (
	"fmt"
	"io"
	"math"
	"sort"
	"time"

	"github.com/shivashis-adhikari/keyfold/internal/logs"
	"github.com/shivashis-adhikari/keyfold/internal/plan"
	"github.com/shivashis-adhikari/keyfold/internal/routes"
)

// the replayable part of a log: one entry per cacheable get, both keys
// already hashed. about 40 bytes a request.
type Trace struct {
	Time  []int64 // unix milliseconds
	Size  []int64
	Cur   []uint64
	Prop  []uint64
	Route []int32 // index into the plan's routes, -1 when outside the plan
	TTL   []int64 // milliseconds, per plan route; the last slot is the default

	Lines       int64 // log lines read
	Skipped     int64 // lines that didn't parse
	Uncacheable int64 // valid lines left out: non-get, uncacheable status or route
	Bytes       int64
	Start, End  time.Time

	CurKeys, PropKeys           int
	CurFootprint, PropFootprint int64 // bytes of distinct objects, last size seen

	// what the cdn itself reported, when the log says
	ObservedHits, ObservedTotal int64

	HasHeaders bool
	HasCookies bool
	Routes     []string // "host pattern" per plan route
	Parse      []string // a few parse errors, for the summary
}

func (t *Trace) Len() int { return len(t.Time) }

// covers the whole log, used for monthly projections
func (t *Trace) Span() time.Duration { return t.End.Sub(t.Start) }

type BuildOptions struct {
	// ttl for requests outside the plan and plan routes whose origin sent
	// no max-age
	DefaultTTL time.Duration
	// keep requests on routes the probe found uncacheable. off by default:
	// counting them would inflate both sides.
	IncludeUncacheable bool
}

// reads every record from the scanner and keys it both ways.
func Build(sc *logs.Scanner, p *plan.Plan, opts BuildOptions) (*Trace, error) {
	if opts.DefaultTTL <= 0 {
		opts.DefaultTTL = time.Hour
	}
	k := plan.NewKeyer(p)
	t := &Trace{}
	for _, r := range p.Routes {
		t.Routes = append(t.Routes, r.Host+" "+r.Pattern)
		ttl := time.Duration(r.TTL) * time.Second
		if ttl <= 0 {
			ttl = opts.DefaultTTL
		}
		t.TTL = append(t.TTL, ttl.Milliseconds())
	}
	t.TTL = append(t.TTL, opts.DefaultTTL.Milliseconds())

	curSeen := map[uint64]int64{}
	propSeen := map[uint64]int64{}
	var buf []byte
	for sc.Scan() {
		r := sc.Record()
		if r.Method != "GET" || !routes.IsCacheableStatus(r.Status) {
			t.Uncacheable++
			continue
		}
		ri := k.Route(r)
		if ri >= 0 && !p.Routes[ri].Cacheable && !opts.IncludeUncacheable {
			t.Uncacheable++
			continue
		}
		if len(r.Header) > 0 {
			t.HasHeaders = true
		}
		if len(r.Cookies) > 0 {
			t.HasCookies = true
		}
		ms := r.Time.UnixMilli()
		if t.Start.IsZero() || r.Time.Before(t.Start) {
			t.Start = r.Time
		}
		if r.Time.After(t.End) {
			t.End = r.Time
		}
		buf = plan.Current(r, buf[:0])
		cur := hashBytes(buf)
		buf = k.Proposed(r, ri, buf[:0])
		prop := hashBytes(buf)

		t.Time = append(t.Time, ms)
		t.Size = append(t.Size, r.Bytes)
		t.Cur = append(t.Cur, cur)
		t.Prop = append(t.Prop, prop)
		t.Route = append(t.Route, int32(ri))
		t.Bytes += r.Bytes
		curSeen[cur] = r.Bytes
		propSeen[prop] = r.Bytes

		switch r.CacheStatus {
		case "":
		case "hit", "stale", "updating", "revalidated":
			t.ObservedHits++
			t.ObservedTotal++
		default:
			t.ObservedTotal++
		}
	}
	t.Lines, t.Skipped, t.Parse = sc.Lines, sc.Skipped, sc.Errors
	if err := sc.Err(); err != nil {
		return t, err
	}
	t.CurKeys, t.PropKeys = len(curSeen), len(propSeen)
	for _, s := range curSeen {
		t.CurFootprint += s
	}
	for _, s := range propSeen {
		t.PropFootprint += s
	}
	t.sortByTime()
	return t, nil
}

func hashBytes(b []byte) uint64 {
	h := uint64(14695981039346656037)
	for _, c := range b {
		h ^= uint64(c)
		h *= 1099511628211
	}
	return h
}

// logpush batches and multi-file inputs arrive slightly out of order.
// ttls and the eviction policies both care, so sort if needed.
func (t *Trace) sortByTime() {
	if sort.SliceIsSorted(t.Time, func(i, j int) bool { return t.Time[i] < t.Time[j] }) {
		return
	}
	idx := make([]int, len(t.Time))
	for i := range idx {
		idx[i] = i
	}
	sort.SliceStable(idx, func(a, b int) bool { return t.Time[idx[a]] < t.Time[idx[b]] })
	t.Time = permute(t.Time, idx)
	t.Size = permute(t.Size, idx)
	t.Cur = permute(t.Cur, idx)
	t.Prop = permute(t.Prop, idx)
	t.Route = permute(t.Route, idx)
}

func permute[T any](xs []T, idx []int) []T {
	out := make([]T, len(xs))
	for i, j := range idx {
		out[i] = xs[j]
	}
	return out
}

// the average object size, used to size tinylfu's sketch
func (t *Trace) avgObject() int64 {
	if t.CurKeys == 0 {
		return 1
	}
	return int64(math.Max(1, float64(t.CurFootprint)/float64(t.CurKeys)))
}

func (t *Trace) Summary(w io.Writer) {
	fmt.Fprintf(w, "%d lines, %d skipped, %d not cacheable, %d replayed over %s\n",
		t.Lines, t.Skipped, t.Uncacheable, t.Len(), t.Span().Round(time.Second))
	fmt.Fprintf(w, "distinct keys: %d now, %d planned (%.1fx fewer)\n", t.CurKeys, t.PropKeys, ratio(t.CurKeys, t.PropKeys))
	fmt.Fprintf(w, "working set:   %s now, %s planned\n", HumanBytes(t.CurFootprint), HumanBytes(t.PropFootprint))
	if t.ObservedTotal > 0 {
		fmt.Fprintf(w, "hit ratio the cdn logged: %.1f%%\n", 100*float64(t.ObservedHits)/float64(t.ObservedTotal))
	}
}

func ratio(a, b int) float64 {
	if b == 0 {
		return 0
	}
	return float64(a) / float64(b)
}

func HumanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}
