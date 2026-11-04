package sim

import (
	"fmt"
	"math"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/shivashis-adhikari/keyfold/internal/cache"
)

// a cache size, either absolute bytes or a fraction of the current key's
// working set. fractions make results comparable across logs of different
// sizes, absolute sizes answer "what does my 64gb edge do".
type Size struct {
	Bytes    int64
	Fraction float64
	Label    string
}

// parses "0.5%,1%,10%,512mb,4gib".
func ParseSizes(s string) ([]Size, error) {
	var out []Size
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if p, ok := strings.CutSuffix(part, "%"); ok {
			f, err := strconv.ParseFloat(p, 64)
			if err != nil || f <= 0 || f > 1000 {
				return nil, fmt.Errorf("bad cache size %q", part)
			}
			out = append(out, Size{Fraction: f / 100, Label: part})
			continue
		}
		b, err := ParseBytes(part)
		if err != nil {
			return nil, err
		}
		out = append(out, Size{Bytes: b, Label: part})
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no cache sizes in %q", s)
	}
	return out, nil
}

func ParseBytes(s string) (int64, error) {
	s = strings.TrimSpace(strings.ToUpper(s))
	mult := int64(1)
	for _, u := range []struct {
		suffix string
		mult   int64
	}{
		{"TIB", 1 << 40}, {"GIB", 1 << 30}, {"MIB", 1 << 20}, {"KIB", 1 << 10},
		{"TB", 1e12}, {"GB", 1e9}, {"MB", 1e6}, {"KB", 1e3}, {"T", 1 << 40}, {"G", 1 << 30}, {"M", 1 << 20}, {"K", 1 << 10}, {"B", 1},
	} {
		if strings.HasSuffix(s, u.suffix) {
			s, mult = strings.TrimSpace(strings.TrimSuffix(s, u.suffix)), u.mult
			break
		}
	}
	f, err := strconv.ParseFloat(s, 64)
	if err != nil || f <= 0 {
		return 0, fmt.Errorf("bad size %q", s)
	}
	return int64(f * float64(mult)), nil
}

func (s Size) bytes(t *Trace) int64 {
	if s.Bytes > 0 {
		return s.Bytes
	}
	return int64(math.Max(1, s.Fraction*float64(t.CurFootprint)))
}

type Stats struct {
	Requests int64 `json:"requests"`
	Hits     int64 `json:"hits"`
	Bytes    int64 `json:"bytes"`
	HitBytes int64 `json:"hit_bytes"`
}

func (s Stats) HitRatio() float64     { return frac(s.Hits, s.Requests) }
func (s Stats) ByteHitRatio() float64 { return frac(s.HitBytes, s.Bytes) }
func (s Stats) OriginRequests() int64 { return s.Requests - s.Hits }
func (s Stats) OriginBytes() int64    { return s.Bytes - s.HitBytes }

func frac(a, b int64) float64 {
	if b == 0 {
		return 0
	}
	return float64(a) / float64(b)
}

type Result struct {
	Policy   string `json:"policy"`
	Size     string `json:"size"`
	Capacity int64  `json:"capacity"`
	Current  Stats  `json:"current"`
	Proposed Stats  `json:"proposed"`
}

type Config struct {
	Policies []string
	Sizes    []Size
	Workers  int
}

// replays the trace for every policy and size, with both keys. the
// infinite-cache bound runs once, as policy "inf".
func Run(t *Trace, cfg Config) ([]Result, error) {
	for _, p := range cfg.Policies {
		if _, err := cache.New(p, 1, 1); err != nil {
			return nil, err
		}
	}
	if cfg.Workers <= 0 {
		cfg.Workers = runtime.GOMAXPROCS(0)
	}
	type job struct {
		res  *Result
		prop bool
	}
	results := make([]Result, 0, len(cfg.Policies)*len(cfg.Sizes)+1)
	for _, p := range cfg.Policies {
		for _, s := range cfg.Sizes {
			results = append(results, Result{Policy: p, Size: s.Label, Capacity: s.bytes(t)})
		}
	}
	results = append(results, Result{Policy: "inf", Size: "-"})

	jobs := make(chan job)
	var wg sync.WaitGroup
	for w := 0; w < cfg.Workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				st := replay(t, j.res.Policy, j.res.Capacity, j.prop, nil)
				if j.prop {
					j.res.Proposed = st
				} else {
					j.res.Current = st
				}
			}
		}()
	}
	for i := range results {
		jobs <- job{&results[i], false}
		jobs <- job{&results[i], true}
	}
	close(jobs)
	wg.Wait()
	return results, nil
}

func newCache(t *Trace, policy string, capacity int64) cache.Cache {
	if policy == "inf" {
		return cache.NewInfinite()
	}
	c, _ := cache.New(policy, capacity, int(capacity/t.avgObject())+1)
	return c
}

// one pass over the trace. a non-nil per-route slice also collects stats
// per plan route, with the last slot for requests outside the plan.
func replay(t *Trace, policy string, capacity int64, prop bool, perRoute []Stats) Stats {
	c := newCache(t, policy, capacity)
	keys := t.Cur
	if prop {
		keys = t.Prop
	}
	var st Stats
	def := t.TTL[len(t.TTL)-1]
	for i, k := range keys {
		ttl := def
		ri := t.Route[i]
		if ri >= 0 {
			ttl = t.TTL[ri]
		}
		now := t.Time[i]
		size := t.Size[i]
		hit := c.Access(k, size, now, now+ttl)
		st.Requests++
		st.Bytes += size
		if hit {
			st.Hits++
			st.HitBytes += size
		}
		if perRoute != nil {
			slot := len(perRoute) - 1
			if ri >= 0 {
				slot = int(ri)
			}
			ps := &perRoute[slot]
			ps.Requests++
			ps.Bytes += size
			if hit {
				ps.Hits++
				ps.HitBytes += size
			}
		}
	}
	return st
}

type RouteResult struct {
	Route    string `json:"route"`
	Current  Stats  `json:"current"`
	Proposed Stats  `json:"proposed"`
}

// replays one configuration with per-route accounting, to show where the
// savings come from.
func ByRoute(t *Trace, policy string, size Size) []RouteResult {
	capacity := size.bytes(t)
	cur := make([]Stats, len(t.Routes)+1)
	prop := make([]Stats, len(t.Routes)+1)
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); replay(t, policy, capacity, false, cur) }()
	go func() { defer wg.Done(); replay(t, policy, capacity, true, prop) }()
	wg.Wait()
	out := make([]RouteResult, 0, len(cur))
	for i := range cur {
		name := "(not in plan)"
		if i < len(t.Routes) {
			name = t.Routes[i]
		}
		if cur[i].Requests == 0 {
			continue
		}
		out = append(out, RouteResult{Route: name, Current: cur[i], Proposed: prop[i]})
	}
	return out
}

// what origin traffic costs. egress is the cloud provider's per-gb price
// for bytes leaving the origin (to the cdn); requests is compute per
// million requests the origin has to serve.
type Costs struct {
	EgressPerGB float64
	PerMillion  float64
}

// projects a stats diff over the trace's span to 30 days.
func (c Costs) Monthly(s Stats, span time.Duration) float64 {
	if span <= 0 {
		return 0
	}
	scale := float64(30*24*time.Hour) / float64(span)
	gb := float64(s.OriginBytes()) / 1e9
	return scale * (gb*c.EgressPerGB + float64(s.OriginRequests())/1e6*c.PerMillion)
}
