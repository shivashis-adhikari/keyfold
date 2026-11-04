// package canary checks a cache key rollout from the outside.
//
// record fetches, for each planned route, a base url and two kinds of
// siblings: ones the new key should fold into the base (dropped params with
// real values, a shuffled query) and ones it must keep apart (a kept param,
// cookie or language changed). it stores a fingerprint of each response.
// record against the origin, or against the edge before the change.
//
// verify replays the same requests through the edge after the rollout, base
// first, so folded siblings are answered from the entry the base created.
// if the new key merged two urls that really differ, the sibling comes back
// with the base's content and its fingerprint no longer matches.
package canary

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/shivashis-adhikari/keyfold/internal/gen"
	"github.com/shivashis-adhikari/keyfold/internal/normalize"
	"github.com/shivashis-adhikari/keyfold/internal/plan"
	"github.com/shivashis-adhikari/keyfold/internal/routes"
)

const (
	Base  = "base"
	Merge = "merge" // same planned key as the base
	Split = "split" // different planned key
)

type Snapshot struct {
	Version int       `json:"version"`
	Taken   time.Time `json:"taken"`
	Target  string    `json:"target"`
	Canary  bool      `json:"canary"`
	Groups  []Group   `json:"groups"`
}

type Group struct {
	Route   string  `json:"route"`
	Entries []Entry `json:"entries"`
}

type Entry struct {
	Kind    string            `json:"kind"`
	Why     string            `json:"why,omitempty"` // what differs from the base
	Host    string            `json:"host"`
	URI     string            `json:"uri"`
	Header  map[string]string `json:"header,omitempty"`
	Cookies map[string]string `json:"cookies,omitempty"`

	FP     normalize.Fingerprint `json:"fingerprint"`
	Stable bool                  `json:"stable"`
	// for pages that differ between two identical requests: the tokens
	// of the first fetch and the ones that moved. verify compares token
	// bags against these instead of the hash.
	Tokens normalize.Tokens `json:"tokens,omitempty"`
	Noise  []string         `json:"noise,omitempty"`
	// shapes of the noise tokens that carry digits (see normalize.shape).
	// a request id comes back with a new value on every fetch, so its
	// shape is what can be recognised later, not its value.
	Shapes []string `json:"shapes,omitempty"`
	Error  string   `json:"error,omitempty"`
}

type Options struct {
	Target     *url.URL
	HostHeader string
	Canary     bool // send the canary header
	Samples    int  // base urls per route
	Siblings   int  // merge siblings per base
	Rate       float64
	Timeout    time.Duration
	Normalizer *normalize.Normalizer
	Client     *http.Client
	Progress   io.Writer
}

func (o *Options) defaults() error {
	if o.Target == nil || o.Target.Host == "" {
		return errors.New("canary: target url is required")
	}
	if o.Samples <= 0 {
		o.Samples = 3
	}
	if o.Siblings <= 0 {
		o.Siblings = 4
	}
	if o.Rate <= 0 {
		o.Rate = 10
	}
	if o.Timeout <= 0 {
		o.Timeout = 15 * time.Second
	}
	if o.Normalizer == nil {
		o.Normalizer, _ = normalize.New(nil)
	}
	if o.Progress == nil {
		o.Progress = io.Discard
	}
	if o.Client == nil {
		o.Client = &http.Client{}
	}
	c := *o.Client
	c.Timeout = o.Timeout
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	o.Client = &c
	return nil
}

// builds the request groups for a plan. exported for tests and for
// "keyfold canary list".
func Groups(p *plan.Plan, samples, siblings int) []Group {
	var out []Group
	for _, r := range p.Routes {
		if !r.Cacheable || !r.Changed() {
			continue
		}
		g := Group{Route: strings.TrimSpace(r.Host + " " + r.Pattern)}
		seen := map[string]bool{}
		n := 0
		for _, s := range r.Samples {
			if n >= samples {
				break
			}
			path, raw, _ := strings.Cut(s, "?")
			base := baseQuery(r, p.Mode, routes.SplitQuery(raw))
			uri := join(path, base)
			if seen[uri] {
				continue
			}
			seen[uri] = true
			n++
			g.Entries = append(g.Entries, Entry{Kind: Base, Host: r.Host, URI: uri})
			g.Entries = append(g.Entries, mergeSiblings(r, path, base, s, siblings)...)
			g.Entries = append(g.Entries, splitSiblings(r, path, base)...)
		}
		if len(g.Entries) > 0 {
			out = append(out, g)
		}
	}
	return out
}

// the query a url keeps under the plan, in its original order
func baseQuery(r *plan.Route, mode string, pairs []routes.Pair) []routes.Pair {
	var out []routes.Pair
	for _, p := range pairs {
		if r.KeepsParam(p.Name, mode) {
			out = append(out, p)
		}
	}
	return out
}

func join(path string, pairs []routes.Pair) string {
	if len(pairs) == 0 {
		return path
	}
	raw := make([]string, len(pairs))
	for i, p := range pairs {
		raw[i] = p.Raw
	}
	return path + "?" + strings.Join(raw, "&")
}

func mergeSiblings(r *plan.Route, path string, base []routes.Pair, original string, n int) []Entry {
	var out []Entry
	add := func(why string, pairs []routes.Pair) {
		if len(out) < n {
			out = append(out, Entry{Kind: Merge, Why: why, Host: r.Host, URI: join(path, pairs)})
		}
	}
	if original != join(path, base) {
		add("original sample", routes.SplitQuery(queryOf(original)))
	}
	// one dropped param at a time with a real value, then all of them
	var all []routes.Pair
	for _, name := range r.Query.Drop {
		vals := r.Values[name]
		if len(vals) == 0 {
			continue
		}
		p := pair(name, vals[0])
		all = append(all, p)
		add("added "+name, append(append([]routes.Pair(nil), base...), p))
		if len(vals) > 1 {
			add("added "+name+" with another value", append([]routes.Pair{pair(name, vals[1])}, base...))
		}
	}
	if len(all) > 1 {
		add("all dropped params", append(append([]routes.Pair(nil), all...), base...))
	}
	if r.Query.Sort && len(base) > 1 {
		rev := make([]routes.Pair, len(base))
		for i := range base {
			rev[i] = base[len(base)-1-i]
		}
		add("query reversed", rev)
	}
	return out
}

func pair(name, value string) routes.Pair {
	return routes.Pair{Name: name, Value: value, Raw: url.QueryEscape(name) + "=" + url.QueryEscape(value)}
}

func queryOf(uri string) string {
	_, q, _ := strings.Cut(uri, "?")
	return q
}

// siblings the new key has to keep apart from the base. they catch a cdn
// config that loses a kept param, or ignores the header and cookie parts.
func splitSiblings(r *plan.Route, path string, base []routes.Pair) []Entry {
	var out []Entry
	for i, p := range base {
		ev := r.Evidence["query:"+p.Name]
		if ev == "" || strings.HasPrefix(ev, "kept by name") {
			continue // no proof this param changes anything
		}
		alt := append([]routes.Pair(nil), base...)
		why := "without " + p.Name
		changed := false
		for _, v := range r.Values[p.Name] {
			if v != p.Value {
				alt[i] = pair(p.Name, v)
				why = p.Name + "=" + v
				changed = true
				break
			}
		}
		if !changed {
			alt = append(alt[:i], alt[i+1:]...)
		}
		out = append(out, Entry{Kind: Split, Why: why, Host: r.Host, URI: join(path, alt)})
		break // one is enough to show kept params are still keyed
	}
	if r.Header.Lang {
		out = append(out, Entry{Kind: Split, Why: "accept-language de", Host: r.Host, URI: join(path, base),
			Header: map[string]string{"Accept-Language": "de-DE,de;q=0.9"}})
	}
	if r.Header.Device {
		out = append(out, Entry{Kind: Split, Why: "mobile user-agent", Host: r.Host, URI: join(path, base),
			Header: map[string]string{"User-Agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1"}})
	}
	for _, c := range r.Cookie.Include {
		if vals := r.CookieValues[c]; len(vals) > 0 {
			out = append(out, Entry{Kind: Split, Why: "cookie " + c + "=" + vals[0], Host: r.Host, URI: join(path, base), Cookies: map[string]string{c: vals[0]}})
		}
	}
	return out
}

type fetcher struct {
	opts Options
	tick *time.Ticker
}

func newFetcher(opts Options) *fetcher {
	return &fetcher{opts: opts, tick: time.NewTicker(time.Duration(float64(time.Second) / opts.Rate))}
}

type response struct {
	fp     normalize.Fingerprint
	tokens normalize.Tokens
	cache  string // hit, miss or "" from the cache status headers
}

func (f *fetcher) get(ctx context.Context, e Entry) (response, error) {
	select {
	case <-f.tick.C:
	case <-ctx.Done():
		return response{}, ctx.Err()
	}
	t := f.opts.Target
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, t.Scheme+"://"+t.Host+e.URI, nil)
	if err != nil {
		return response{}, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	for k, v := range e.Header {
		req.Header.Set(k, v)
	}
	if len(e.Cookies) > 0 {
		var parts []string
		for k, v := range e.Cookies {
			parts = append(parts, k+"="+v)
		}
		sort.Strings(parts)
		req.Header.Set("Cookie", strings.Join(parts, "; "))
	}
	if f.opts.Canary {
		req.Header.Set(gen.CanaryHeader, "1")
	}
	req.Host = e.Host
	if f.opts.HostHeader != "" {
		req.Host = f.opts.HostHeader
	}
	if req.Host == "" {
		req.Host = t.Host
	}
	resp, err := f.opts.Client.Do(req)
	if err != nil {
		return response{}, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return response{}, err
	}
	fp, norm := f.opts.Normalizer.Fingerprint(resp.Header, resp.StatusCode, body)
	return response{fp: fp, tokens: normalize.Tokenize(norm), cache: cacheStatus(resp.Header)}, nil
}

// reads the cache status headers cloudflare, rfc 9211 caches (souin) and
// the usual nginx/varnish setups send.
func cacheStatus(h http.Header) string {
	if v := strings.ToLower(h.Get("Cf-Cache-Status")); v != "" {
		return v
	}
	if v := strings.ToLower(h.Get("Cache-Status")); v != "" {
		switch {
		case strings.Contains(v, "; hit"):
			return "hit"
		case strings.Contains(v, "fwd="):
			return "miss"
		}
	}
	for _, k := range []string{"X-Cache", "X-Cache-Status"} {
		if v := strings.ToLower(h.Get(k)); v != "" {
			if strings.Contains(v, "hit") {
				return "hit"
			}
			return "miss"
		}
	}
	return ""
}

// fetches every entry twice and stores what came back.
func Record(ctx context.Context, p *plan.Plan, opts Options) (*Snapshot, error) {
	if err := opts.defaults(); err != nil {
		return nil, err
	}
	f := newFetcher(opts)
	defer f.tick.Stop()
	snap := &Snapshot{Version: 1, Taken: time.Now().UTC(), Target: opts.Target.String(), Canary: opts.Canary,
		Groups: Groups(p, opts.Samples, opts.Siblings)}
	n := 0
	for gi := range snap.Groups {
		g := &snap.Groups[gi]
		for ei := range g.Entries {
			e := &g.Entries[ei]
			a, err := f.get(ctx, *e)
			if err != nil {
				e.Error = err.Error()
				continue
			}
			b, err := f.get(ctx, *e)
			if err != nil {
				e.Error = err.Error()
				continue
			}
			n += 2
			e.FP = a.fp
			e.Stable = a.fp == b.fp
			if !e.Stable {
				var v normalize.Volatile
				v.Add(a.tokens)
				v.Add(b.tokens)
				// a third look, rotating content needs more than two
				if c, err := f.get(ctx, *e); err == nil {
					v.Add(c.tokens)
					n++
				}
				e.Tokens = a.tokens
				e.Noise = v.Tokens()
				shapes := map[string]bool{}
				for _, tok := range e.Noise {
					if sh := normalize.Shape(tok); sh != "" && !shapes[sh] {
						shapes[sh] = true
						e.Shapes = append(e.Shapes, sh)
					}
				}
				sort.Strings(e.Shapes)
			}
		}
		fmt.Fprintf(opts.Progress, "  recorded %-40s %d urls\n", g.Route, len(g.Entries))
	}
	fmt.Fprintf(opts.Progress, "%d requests\n", n)
	return snap, ctx.Err()
}

func (s *Snapshot) Save(path string) error {
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o644)
}

func Load(path string) (*Snapshot, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var s Snapshot
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &s, nil
}
