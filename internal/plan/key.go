package plan

import (
	"sort"

	"github.com/shivashis-adhikari/keyfold/internal/logs"
	"github.com/shivashis-adhikari/keyfold/internal/routes"
)

// builds cache keys for log records under the plan. it is not safe for
// concurrent use because it reuses scratch buffers.
type Keyer struct {
	plan    *Plan
	m       *routes.Matcher
	drop    []map[string]bool
	keep    []map[string]bool
	scratch []routes.Pair
}

func NewKeyer(p *Plan) *Keyer {
	k := &Keyer{plan: p}
	hosts := make([]string, len(p.Routes))
	pats := make([]string, len(p.Routes))
	for i, r := range p.Routes {
		hosts[i], pats[i] = r.Host, r.Pattern
		drop := map[string]bool{}
		for _, n := range r.Query.Drop {
			drop[n] = true
		}
		keep := map[string]bool{}
		for _, n := range r.Query.Keep {
			keep[n] = true
		}
		for _, n := range r.Query.Unverified {
			keep[n] = true
		}
		k.drop = append(k.drop, drop)
		k.keep = append(k.keep, keep)
	}
	k.m = routes.NewMatcher(hosts, pats)
	return k
}

// the plan route a record falls under, or -1.
func (k *Keyer) Route(r *logs.Record) int { return k.m.Match(r.Host, r.Path) }

// the key a cdn builds by default: scheme, host and the full request uri,
// query untouched. that is cloudflare's default; caddy's cache handler adds
// the method, which doesn't matter here since only gets are simulated.
func Current(r *logs.Record, buf []byte) []byte {
	buf = append(buf, r.Scheme...)
	buf = append(buf, "://"...)
	buf = append(buf, r.Host...)
	buf = append(buf, r.Path...)
	if r.RawQuery != "" {
		buf = append(buf, '?')
		buf = append(buf, r.RawQuery...)
	}
	return buf
}

// the key under the plan for a record on route i. records outside the plan
// (i < 0) get the current key.
func (k *Keyer) Proposed(r *logs.Record, i int, buf []byte) []byte {
	if i < 0 {
		return Current(r, buf)
	}
	rt := k.plan.Routes[i]
	buf = append(buf, r.Scheme...)
	buf = append(buf, "://"...)
	buf = append(buf, r.Host...)
	buf = append(buf, r.Path...)

	pairs := k.scratch[:0]
	for _, p := range routes.SplitQuery(r.RawQuery) {
		if k.plan.Mode == Tight {
			if !k.keep[i][p.Name] {
				continue
			}
		} else if k.drop[i][p.Name] {
			continue
		}
		pairs = append(pairs, p)
	}
	if rt.Query.Sort {
		sort.SliceStable(pairs, func(a, b int) bool {
			if pairs[a].Name != pairs[b].Name {
				return pairs[a].Name < pairs[b].Name
			}
			return pairs[a].Raw < pairs[b].Raw
		})
	}
	for j, p := range pairs {
		if j == 0 {
			buf = append(buf, '?')
		} else {
			buf = append(buf, '&')
		}
		buf = append(buf, p.Raw...)
	}
	k.scratch = pairs

	// header and cookie parts. when the log didn't record them every
	// request gets the same empty value, which merges them: the simulator
	// says so in its output.
	if rt.Header.Lang {
		buf = append(buf, "|lang="...)
		buf = append(buf, routes.FirstLanguage(r.Header["accept-language"])...)
	}
	if rt.Header.Device {
		buf = append(buf, "|dev="...)
		if ua := r.Header["user-agent"]; ua != "" {
			buf = append(buf, routes.DeviceType(ua)...)
		}
	}
	for _, h := range rt.Header.Include {
		buf = append(buf, "|h:"...)
		buf = append(buf, h...)
		buf = append(buf, '=')
		buf = append(buf, r.Header[h]...)
	}
	for _, c := range rt.Cookie.Include {
		buf = append(buf, "|c:"...)
		buf = append(buf, c...)
		buf = append(buf, '=')
		buf = append(buf, r.Cookies[c]...)
	}
	for _, c := range rt.Cookie.Presence {
		buf = append(buf, "|p:"...)
		buf = append(buf, c...)
		if _, ok := r.Cookies[c]; ok {
			buf = append(buf, "=1"...)
		}
	}
	return buf
}
