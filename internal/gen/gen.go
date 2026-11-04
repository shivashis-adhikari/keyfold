// package gen writes cdn and proxy config from a plan.
package gen

import (
	"sort"
	"strings"

	"github.com/shivashis-adhikari/keyfold/internal/plan"
)

// gates every generated rule in canary mode. only requests
// carrying it get the new key, and the header is part of the key, so canary
// entries never mix with what real users are served.
const CanaryHeader = "X-Keyfold-Canary"

type Options struct {
	Canary bool
	// cloudflare only: free, pro, business or enterprise. custom query,
	// header and cookie keys are enterprise features.
	CFPlan string
	// cloudflare only: use the regex operator for paths. needs business or
	// enterprise. wildcard plus a slash-count guard is used otherwise.
	CFRegex bool
}

// routes that need a rule, most general first. cloudflare applies later
// matching rules over earlier ones and the other generators use first-match,
// so each generator orders these itself from this list.
func routesToEmit(p *plan.Plan) []*plan.Route {
	var out []*plan.Route
	for _, r := range p.Routes {
		if r.Cacheable && r.Changed() {
			out = append(out, r)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		a, b := placeholders(out[i].Pattern), placeholders(out[j].Pattern)
		if a != b {
			return a > b
		}
		if out[i].Host != out[j].Host {
			return out[i].Host < out[j].Host
		}
		return out[i].Pattern < out[j].Pattern
	})
	return out
}

func placeholders(p string) int { return strings.Count(p, "{") }

// whether the origin reflected x-forwarded-host anywhere in the plan
func reflectsForwardedHost(p *plan.Plan) []*plan.Route {
	var out []*plan.Route
	for _, r := range p.Routes {
		if !r.Cacheable {
			continue
		}
		for _, f := range r.Flags {
			if f.Kind == "unkeyed-input" && f.Name == "x-forwarded-host" {
				out = append(out, r)
				break
			}
		}
	}
	return out
}

// params the key keeps in tight mode
func kept(r *plan.Route) []string {
	out := append(append([]string(nil), r.Query.Keep...), r.Query.Unverified...)
	sort.Strings(out)
	return out
}

func slug(s string) string {
	var b strings.Builder
	last := byte('_')
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9':
		case c >= 'A' && c <= 'Z':
			c += 'a' - 'A'
		default:
			c = '_'
		}
		if c == '_' && last == '_' {
			continue
		}
		b.WriteByte(c)
		last = c
	}
	return strings.Trim(b.String(), "_")
}
