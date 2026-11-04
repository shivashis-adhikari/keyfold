package routes

import (
	"math/rand/v2"
	"sort"
	"time"

	"github.com/shivashis-adhikari/keyfold/internal/logs"
)

// what the logs say about each route: how much traffic it gets,
// which params and cookies show up, and a sample of real urls.
type Inventory struct {
	Requests int64     `json:"requests"`
	Start    time.Time `json:"start"`
	End      time.Time `json:"end"`
	Routes   []*Route  `json:"routes"`

	// whether the logs carried request headers / cookies at all. without
	// them the simulator can't model header or cookie key parts.
	HasHeaders bool `json:"has_headers"`
	HasCookies bool `json:"has_cookies"`
}

type Route struct {
	Host        string   `json:"host"`
	Pattern     string   `json:"pattern"`
	Requests    int64    `json:"requests"`
	Cacheable   int64    `json:"cacheable"`
	Bytes       int64    `json:"bytes"`
	UniqueURLs  int64    `json:"unique_urls"`
	UniquePaths int64    `json:"unique_paths"`
	Params      []*Param `json:"params,omitempty"`
	Cookies     []*Param `json:"cookies,omitempty"`
	Samples     []Sample `json:"samples,omitempty"`
}

// summarises one query param (or cookie) on a route.
type Param struct {
	Name     string  `json:"name"`
	Requests int64   `json:"requests"`
	Distinct int64   `json:"distinct"`
	Top      []Value `json:"top,omitempty"`
}

type Value struct {
	V string `json:"v"`
	N int64  `json:"n"`
}

// one real request, kept so the prober has something to replay.
// only a few headers are kept, and cookie values only when the name doesn't
// look like a credential.
type Sample struct {
	URI     string            `json:"uri"`
	Header  map[string]string `json:"header,omitempty"`
	Cookies map[string]string `json:"cookies,omitempty"`
}

// unique urls per unique path: how many cache entries the
// full-url key makes for each thing the route actually serves.
func (r *Route) Fragmentation() float64 {
	if r.UniquePaths == 0 {
		return 0
	}
	return float64(r.UniqueURLs) / float64(r.UniquePaths)
}

// returns the stats for a query param, or nil.
func (r *Route) Param(name string) *Param {
	for _, p := range r.Params {
		if p.Name == name {
			return p
		}
	}
	return nil
}

func (r *Route) Cookie(name string) *Param {
	for _, p := range r.Cookies {
		if p.Name == name {
			return p
		}
	}
	return nil
}

// tunes the inventory builder.
type Options struct {
	// literal siblings at one path position before they fold into a
	// placeholder. 20 means a 21st product slug turns /products/x into
	// /products/{slug}.
	CollapseAt int
	// reservoir size per route.
	Samples int
	// distinct values remembered per param, for the top list and for picking
	// replacement values while probing.
	MaxValues int
	Seed      uint64
}

func (o *Options) defaults() {
	if o.CollapseAt <= 0 {
		o.CollapseAt = 20
	}
	if o.Samples <= 0 {
		o.Samples = 24
	}
	if o.MaxValues <= 0 {
		o.MaxValues = 64
	}
	if o.Seed == 0 {
		o.Seed = 1
	}
}

// headers worth keeping on samples. the prober only varies these.
var sampleHeaders = []string{"accept", "accept-language", "user-agent"}

// accumulates records into pre-templates (paths after the cheap
// per-segment classification) and folds them into routes in finish().
type Builder struct {
	opts Options
	rng  *rand.Rand
	pre  map[string]*acc

	requests   int64
	start, end time.Time
	hasHeaders bool
	hasCookies bool
}

type acc struct {
	host string
	segs []string

	requests, cacheable, bytes int64
	urls, paths                distinct
	params, cookies            map[string]*paramAcc

	seen     int64 // cacheable requests offered to the reservoir
	samples  []Sample
	coverage map[string]Sample // first url seen for each param name
}

type paramAcc struct {
	requests int64
	values   map[string]int64
	distinct distinct
}

func NewBuilder(opts Options) *Builder {
	opts.defaults()
	return &Builder{
		opts: opts,
		rng:  rand.New(rand.NewPCG(opts.Seed, opts.Seed^0x9e3779b97f4a7c15)),
		pre:  make(map[string]*acc),
	}
}

// the set of status codes rfc 9111 lets a shared cache
// store without explicit freshness info, plus 206 which cdns handle
// themselves.
func IsCacheableStatus(code int) bool {
	switch code {
	case 200, 203, 204, 206, 300, 301, 308, 404, 405, 410, 414, 501:
		return true
	}
	return false
}

func (b *Builder) Add(r *logs.Record) {
	b.requests++
	if !r.Time.IsZero() {
		if b.start.IsZero() || r.Time.Before(b.start) {
			b.start = r.Time
		}
		if r.Time.After(b.end) {
			b.end = r.Time
		}
	}
	if len(r.Header) > 0 {
		b.hasHeaders = true
	}
	if len(r.Cookies) > 0 {
		b.hasCookies = true
	}

	segs := splitPath(r.Path)
	for i, s := range segs {
		segs[i] = classify(s)
	}
	key := r.Host + " " + joinPath(segs)
	a := b.pre[key]
	if a == nil {
		a = &acc{host: r.Host, segs: segs, params: map[string]*paramAcc{}, cookies: map[string]*paramAcc{}}
		b.pre[key] = a
	}
	a.requests++
	a.bytes += r.Bytes
	a.urls.add(hashString(r.Path + "?" + r.RawQuery))
	a.paths.add(hashString(r.Path))

	pairs := SplitQuery(r.RawQuery)
	for _, p := range pairs {
		b.count(a.params, p.Name, p.Value, false)
	}
	for name, v := range r.Cookies {
		b.count(a.cookies, name, v, IsSensitive(name))
	}

	if (r.Method != "GET" && r.Method != "HEAD") || !IsCacheableStatus(r.Status) {
		return
	}
	a.cacheable++
	b.sample(a, r, pairs)
}

func (b *Builder) count(m map[string]*paramAcc, name, value string, hide bool) {
	p := m[name]
	if p == nil {
		p = &paramAcc{values: map[string]int64{}}
		m[name] = p
	}
	p.requests++
	p.distinct.add(hashString(value))
	if hide {
		value = ""
	}
	if _, ok := p.values[value]; ok || len(p.values) < b.opts.MaxValues {
		p.values[value]++
	}
}

func (b *Builder) sample(a *acc, r *logs.Record, pairs []Pair) {
	var s *Sample
	mk := func() Sample {
		if s == nil {
			v := makeSample(r)
			s = &v
		}
		return *s
	}
	for _, p := range pairs {
		if a.coverage == nil {
			a.coverage = map[string]Sample{}
		}
		if _, ok := a.coverage[p.Name]; !ok {
			a.coverage[p.Name] = mk()
		}
	}
	// plain reservoir sampling, so samples follow traffic
	a.seen++
	if len(a.samples) < b.opts.Samples {
		a.samples = append(a.samples, mk())
	} else if j := b.rng.Int64N(a.seen); j < int64(b.opts.Samples) {
		a.samples[j] = mk()
	}
}

func makeSample(r *logs.Record) Sample {
	s := Sample{URI: r.URI()}
	for _, h := range sampleHeaders {
		if v := r.Header[h]; v != "" {
			if s.Header == nil {
				s.Header = map[string]string{}
			}
			s.Header[h] = v
		}
	}
	for name, v := range r.Cookies {
		if IsSensitive(name) {
			continue
		}
		if s.Cookies == nil {
			s.Cookies = map[string]string{}
		}
		s.Cookies[name] = v
	}
	return s
}

// folds pre-templates into routes and returns them busiest first.
func (b *Builder) Finish() *Inventory {
	byHost := map[string]*tnode{}
	for _, a := range b.pre {
		root := byHost[a.host]
		if root == nil {
			root = newTnode()
			byHost[a.host] = root
		}
		n := root
		for _, s := range a.segs {
			n = n.child(s)
		}
		n.accs = append(n.accs, a)
	}

	inv := &Inventory{Requests: b.requests, Start: b.start, End: b.end, HasHeaders: b.hasHeaders, HasCookies: b.hasCookies}
	for host, root := range byHost {
		root.sum()
		collapse(root, b.opts.CollapseAt)
		root.walk(nil, func(segs []string, accs []*acc) {
			inv.Routes = append(inv.Routes, b.merge(host, joinPath(segs), accs))
		})
	}
	sort.Slice(inv.Routes, func(i, j int) bool {
		ri, rj := inv.Routes[i], inv.Routes[j]
		if ri.Requests != rj.Requests {
			return ri.Requests > rj.Requests
		}
		if ri.Host != rj.Host {
			return ri.Host < rj.Host
		}
		return ri.Pattern < rj.Pattern
	})
	return inv
}

func (b *Builder) merge(host, pattern string, accs []*acc) *Route {
	r := &Route{Host: host, Pattern: pattern}
	var urls, paths distinct
	params := map[string]*paramAcc{}
	cookies := map[string]*paramAcc{}
	coverage := map[string]Sample{}
	var samples []Sample
	// biggest first so the merged reservoir leans on the busy pre-templates
	sort.Slice(accs, func(i, j int) bool { return accs[i].requests > accs[j].requests })
	for _, a := range accs {
		r.Requests += a.requests
		r.Cacheable += a.cacheable
		r.Bytes += a.bytes
		urls.merge(&a.urls)
		paths.merge(&a.paths)
		mergeParams(params, a.params, b.opts.MaxValues)
		mergeParams(cookies, a.cookies, b.opts.MaxValues)
		for k, s := range a.coverage {
			if _, ok := coverage[k]; !ok {
				coverage[k] = s
			}
		}
		samples = append(samples, a.samples...)
	}
	r.UniqueURLs = urls.count()
	r.UniquePaths = paths.count()
	r.Params = finishParams(params)
	r.Cookies = finishParams(cookies)

	// coverage samples first (one per param, rarest param first) so every
	// param has at least one url carrying it, then the traffic sample.
	seen := map[string]bool{}
	names := make([]string, 0, len(coverage))
	for k := range coverage {
		names = append(names, k)
	}
	sort.Slice(names, func(i, j int) bool {
		pi, pj := params[names[i]], params[names[j]]
		if pi.requests != pj.requests {
			return pi.requests < pj.requests
		}
		return names[i] < names[j]
	})
	for _, k := range names {
		s := coverage[k]
		if !seen[s.URI] {
			seen[s.URI] = true
			r.Samples = append(r.Samples, s)
		}
	}
	for _, s := range samples {
		if len(r.Samples) >= b.opts.Samples*2 {
			break
		}
		if !seen[s.URI] {
			seen[s.URI] = true
			r.Samples = append(r.Samples, s)
		}
	}
	return r
}

func mergeParams(dst, src map[string]*paramAcc, maxValues int) {
	for name, p := range src {
		d := dst[name]
		if d == nil {
			d = &paramAcc{values: map[string]int64{}}
			dst[name] = d
		}
		d.requests += p.requests
		d.distinct.merge(&p.distinct)
		for v, n := range p.values {
			if _, ok := d.values[v]; ok || len(d.values) < maxValues {
				d.values[v] += n
			}
		}
	}
}

func finishParams(m map[string]*paramAcc) []*Param {
	out := make([]*Param, 0, len(m))
	for name, p := range m {
		pp := &Param{Name: name, Requests: p.requests, Distinct: p.distinct.count()}
		for v, n := range p.values {
			pp.Top = append(pp.Top, Value{V: v, N: n})
		}
		sort.Slice(pp.Top, func(i, j int) bool {
			if pp.Top[i].N != pp.Top[j].N {
				return pp.Top[i].N > pp.Top[j].N
			}
			return pp.Top[i].V < pp.Top[j].V
		})
		if len(pp.Top) > 8 {
			pp.Top = pp.Top[:8]
		}
		out = append(out, pp)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Requests != out[j].Requests {
			return out[i].Requests > out[j].Requests
		}
		return out[i].Name < out[j].Name
	})
	return out
}

// the trie used for folding. each node is one pattern segment.
type tnode struct {
	children map[string]*tnode
	accs     []*acc
	reqs     int64 // requests in this subtree, filled in by sum()
}

func newTnode() *tnode { return &tnode{children: map[string]*tnode{}} }

func (n *tnode) child(seg string) *tnode {
	c := n.children[seg]
	if c == nil {
		c = newTnode()
		n.children[seg] = c
	}
	return c
}

func (n *tnode) sum() int64 {
	n.reqs = 0
	for _, a := range n.accs {
		n.reqs += a.requests
	}
	for _, c := range n.children {
		n.reqs += c.sum()
	}
	return n.reqs
}

// folds high-cardinality literal children into a placeholder, bottom up.
// literals are grouped by file extension so /img/{name}.png and
// /img/{name}.svg stay apart. a literal that carries a big share of the
// node's traffic is a section of the site (like /products next to a pile of
// one-off pages), not a slug, so it keeps its own route.
func collapse(n *tnode, k int) {
	for _, c := range n.children {
		collapse(c, k)
	}
	groups := map[string][]string{}
	for seg := range n.children {
		if seg == "" || isPlaceholder(seg) {
			continue
		}
		ext := ""
		if _, e, ok := splitExt(seg); ok {
			ext = e
		}
		groups[ext] = append(groups[ext], seg)
	}
	for ext, segs := range groups {
		if len(segs) <= k {
			continue
		}
		target := phSlug
		if ext != "" {
			target = phName + ext
		}
		folded := false
		for _, seg := range segs {
			c := n.children[seg]
			if n.reqs > 0 && c.reqs*10 >= n.reqs {
				continue
			}
			delete(n.children, seg)
			if dst := n.children[target]; dst != nil {
				mergeNodes(dst, c)
			} else {
				n.children[target] = c
			}
			folded = true
		}
		if folded {
			collapse(n.children[target], k)
		}
	}
}

func mergeNodes(dst, src *tnode) {
	dst.accs = append(dst.accs, src.accs...)
	dst.reqs += src.reqs
	for seg, c := range src.children {
		if d := dst.children[seg]; d != nil {
			mergeNodes(d, c)
		} else {
			dst.children[seg] = c
		}
	}
}

func (n *tnode) walk(prefix []string, fn func([]string, []*acc)) {
	if len(n.accs) > 0 {
		fn(append([]string(nil), prefix...), n.accs)
	}
	keys := make([]string, 0, len(n.children))
	for k := range n.children {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		n.children[k].walk(append(prefix, k), fn)
	}
}
