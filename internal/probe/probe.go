// package probe re-requests sampled urls against your origin, changing one
// query param, header or cookie at a time, and records whether the response
// changed. that evidence is what the key synthesiser works from.
package probe

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/shivashis-adhikari/keyfold/internal/normalize"
	"github.com/shivashis-adhikari/keyfold/internal/routes"
)

const (
	Changes = "changes"
	Noise   = "noise"
	Unknown = "unknown"
	Failed  = "error"
)

type Options struct {
	// where probe requests go. point this at the origin, not the cdn: a
	// cache in between answers every variant with the same stored copy and
	// everything looks like noise.
	Origin *url.URL
	// host header to send. defaults to the host from the logs, or the
	// origin's own host when the logs have none.
	HostHeader string

	Routes      int
	Samples     int
	Baselines   int
	Rate        float64 // requests per second, across all workers
	Concurrency int
	Timeout     time.Duration
	MaxBody     int64
	Insecure    bool // skip tls verification, for origins with internal certs

	Header  http.Header       // added to every request
	Cookies map[string]string // added to every request, and probed
	// if set, a param with this name and a random value goes on every
	// request. use it when the origin sits behind its own cache.
	CacheBuster string
	SkipHeaders bool

	Normalizer *normalize.Normalizer
	Progress   io.Writer
	// for tests
	Client *http.Client
}

func (o *Options) defaults() error {
	if o.Origin == nil || o.Origin.Host == "" {
		return errors.New("probe: origin url is required")
	}
	if o.Origin.Scheme != "http" && o.Origin.Scheme != "https" {
		return fmt.Errorf("probe: origin scheme %q, want http or https", o.Origin.Scheme)
	}
	if o.Routes <= 0 {
		o.Routes = 25
	}
	if o.Samples <= 0 {
		o.Samples = 4
	}
	if o.Baselines < 2 {
		o.Baselines = 3
	}
	if o.Rate <= 0 {
		o.Rate = 10
	}
	if o.Concurrency <= 0 {
		o.Concurrency = 4
	}
	if o.Timeout <= 0 {
		o.Timeout = 15 * time.Second
	}
	if o.MaxBody <= 0 {
		o.MaxBody = 8 << 20
	}
	if o.Normalizer == nil {
		o.Normalizer, _ = normalize.New(nil)
	}
	if o.Progress == nil {
		o.Progress = io.Discard
	}
	return nil
}

type Report struct {
	Version  int               `json:"version"`
	Origin   string            `json:"origin"`
	Started  time.Time         `json:"started"`
	Finished time.Time         `json:"finished"`
	Requests int               `json:"requests"`
	Routes   []*RouteResult    `json:"routes"`
	Inv      *routes.Inventory `json:"inventory"`
	Options  map[string]string `json:"options,omitempty"`
}

type RouteResult struct {
	Host    string          `json:"host"`
	Pattern string          `json:"pattern"`
	Cache   CacheInfo       `json:"cache"`
	Samples []*SampleResult `json:"samples"`
}

// what the origin's own headers say about caching this route.
type CacheInfo struct {
	Status       int      `json:"status"`
	CacheControl string   `json:"cache_control,omitempty"`
	Vary         []string `json:"vary,omitempty"`
	SetCookie    bool     `json:"set_cookie,omitempty"`
	Cacheable    bool     `json:"cacheable"`
	TTL          int64    `json:"ttl,omitempty"` // seconds
	Why          string   `json:"why,omitempty"`
}

type SampleResult struct {
	URI      string                `json:"uri"`
	Stable   bool                  `json:"stable"`
	Volatile int                   `json:"volatile_tokens,omitempty"`
	Drifted  bool                  `json:"drifted,omitempty"`
	Baseline normalize.Fingerprint `json:"baseline"`
	Results  []Result              `json:"results"`
	Requests int                   `json:"requests"`
	Error    string                `json:"error,omitempty"`
}

type Result struct {
	Part    string `json:"part"` // query, header, cookie, order
	Name    string `json:"name"`
	Op      string `json:"op"` // drop, mutate, add, same-class, other-class, reorder
	Value   string `json:"value,omitempty"`
	Verdict string `json:"verdict"`
	Detail  string `json:"detail,omitempty"`
}

type prober struct {
	opts   Options
	client *http.Client
	tick   *time.Ticker
	mu     sync.Mutex
	sent   int
	buster int
	inv    *routes.Inventory
}

// probes the busiest cacheable routes in the inventory.
func Run(ctx context.Context, inv *routes.Inventory, opts Options) (*Report, error) {
	if err := opts.defaults(); err != nil {
		return nil, err
	}
	p := &prober{opts: opts, inv: inv}
	p.client = opts.Client
	if p.client == nil {
		tr := http.DefaultTransport.(*http.Transport).Clone()
		tr.MaxIdleConnsPerHost = opts.Concurrency
		if opts.Insecure {
			tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec // opt-in, for internal origins
		}
		p.client = &http.Client{Transport: tr}
	}
	// redirects are responses too. following them would hide a param that
	// only changes where you get sent.
	c := *p.client
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	c.Timeout = opts.Timeout
	p.client = &c
	p.tick = time.NewTicker(time.Duration(float64(time.Second) / opts.Rate))
	defer p.tick.Stop()

	rep := &Report{Version: 1, Origin: opts.Origin.String(), Started: time.Now().UTC(), Inv: inv}

	type job struct {
		route  *routes.Route
		rr     *RouteResult
		sample routes.Sample
		first  bool
		idx    int
	}
	var jobs []job
	picked := pickRoutes(inv, opts.Routes)
	for _, r := range picked {
		rr := &RouteResult{Host: r.Host, Pattern: r.Pattern}
		rep.Routes = append(rep.Routes, rr)
		samples := pickSamples(r, opts.Samples)
		rr.Samples = make([]*SampleResult, len(samples))
		for i, s := range samples {
			jobs = append(jobs, job{route: r, rr: rr, sample: s, first: i == 0, idx: i})
		}
	}
	fmt.Fprintf(opts.Progress, "probing %d routes, %d sample urls, %.0f req/s\n", len(picked), len(jobs), opts.Rate)

	var wg sync.WaitGroup
	ch := make(chan job)
	for w := 0; w < opts.Concurrency; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range ch {
				sr, ci := p.sample(ctx, j.route, j.sample, j.first)
				j.rr.Samples[j.idx] = sr
				if j.first {
					j.rr.Cache = ci
				}
				changes := 0
				for _, r := range sr.Results {
					if r.Verdict == Changes {
						changes++
					}
				}
				p.mu.Lock()
				fmt.Fprintf(opts.Progress, "  %-36s %s  %d requests, %d of %d parts change the response\n",
					trim(j.route.Pattern, 36), trim(j.sample.URI, 60), sr.Requests, changes, len(sr.Results))
				p.mu.Unlock()
			}
		}()
	}
	for _, j := range jobs {
		select {
		case ch <- j:
		case <-ctx.Done():
		}
	}
	close(ch)
	wg.Wait()
	rep.Finished = time.Now().UTC()
	rep.Requests = p.sent
	return rep, ctx.Err()
}

func trim(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-3] + "..."
}

// busiest first by cacheable requests. a route nobody can cache isn't
// worth probing.
func pickRoutes(inv *routes.Inventory, n int) []*routes.Route {
	rs := make([]*routes.Route, 0, len(inv.Routes))
	for _, r := range inv.Routes {
		if r.Cacheable > 0 && len(r.Samples) > 0 {
			rs = append(rs, r)
		}
	}
	sort.SliceStable(rs, func(i, j int) bool { return rs[i].Cacheable > rs[j].Cacheable })
	if len(rs) > n {
		rs = rs[:n]
	}
	return rs
}

// greedy cover weighted by traffic: keep taking the sample whose uncovered
// params carry the most requests, so the params that matter for the hit
// ratio get tested first. 2xx samples go first, error pages make poor
// baselines.
func pickSamples(r *routes.Route, n int) []routes.Sample {
	weight := map[string]int64{}
	for _, p := range r.Params {
		weight[p.Name] = p.Requests
	}
	pool := make([]routes.Sample, 0, len(r.Samples))
	for _, s := range r.Samples {
		if s.Status >= 200 && s.Status < 300 {
			pool = append(pool, s)
		}
	}
	for _, s := range r.Samples {
		if s.Status < 200 || s.Status >= 300 {
			pool = append(pool, s)
		}
	}
	covered := map[string]bool{}
	used := make([]bool, len(pool))
	var out []routes.Sample
	for len(out) < n {
		best, bestW := -1, int64(0)
		for i, s := range pool {
			if used[i] {
				continue
			}
			var w int64
			counted := map[string]bool{}
			for _, p := range routes.SplitQuery(queryOf(s.URI)) {
				if !covered[p.Name] && !counted[p.Name] {
					counted[p.Name] = true
					w += weight[p.Name] + 1
				}
			}
			if w > bestW {
				best, bestW = i, w
			}
		}
		if best < 0 {
			break
		}
		used[best] = true
		out = append(out, pool[best])
		for _, p := range routes.SplitQuery(queryOf(pool[best].URI)) {
			covered[p.Name] = true
		}
	}
	for i, s := range pool {
		if len(out) >= n {
			break
		}
		if !used[i] {
			out = append(out, s)
		}
	}
	return out
}

func queryOf(uri string) string {
	_, q, _ := strings.Cut(uri, "?")
	return q
}

func pathOf(uri string) string {
	p, _, _ := strings.Cut(uri, "?")
	return p
}

// parses the origin's cache headers into a yes/no plus a ttl.
func cacheInfo(status int, h http.Header) CacheInfo {
	ci := CacheInfo{Status: status, CacheControl: h.Get("Cache-Control"), SetCookie: len(h.Values("Set-Cookie")) > 0}
	for _, v := range h.Values("Vary") {
		for _, f := range strings.Split(v, ",") {
			if f = strings.TrimSpace(f); f != "" {
				ci.Vary = append(ci.Vary, strings.ToLower(f))
			}
		}
	}
	var maxAge, sMaxAge int64 = -1, -1
	for _, d := range strings.Split(strings.ToLower(ci.CacheControl), ",") {
		d = strings.TrimSpace(d)
		name, val, _ := strings.Cut(d, "=")
		switch name {
		case "no-store":
			ci.Why = "cache-control: no-store"
		case "private":
			ci.Why = "cache-control: private"
		case "max-age":
			maxAge, _ = strconv.ParseInt(strings.Trim(val, `"`), 10, 64)
		case "s-maxage":
			sMaxAge, _ = strconv.ParseInt(strings.Trim(val, `"`), 10, 64)
		}
	}
	switch {
	case sMaxAge >= 0:
		ci.TTL = sMaxAge
	case maxAge >= 0:
		ci.TTL = maxAge
	}
	switch {
	case ci.Why != "":
	case !routes.IsCacheableStatus(status):
		ci.Why = fmt.Sprintf("status %d", status)
	case ci.SetCookie:
		ci.Why = "response sets a cookie"
	case ci.TTL == 0 && (sMaxAge == 0 || maxAge == 0):
		ci.Why = "max-age=0"
	}
	ci.Cacheable = ci.Why == ""
	return ci
}
