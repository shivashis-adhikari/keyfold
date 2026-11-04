// package synth turns probe evidence into a cache key plan.
//
// the rule is simple and deliberately one-sided: a request part leaves the
// key only when every probe that touched it came back as noise, and enough
// probes did. anything that changed the response, anything inconclusive and
// anything never tested stays in.
package synth

import (
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/shivashis-adhikari/keyfold/internal/plan"
	"github.com/shivashis-adhikari/keyfold/internal/probe"
	"github.com/shivashis-adhikari/keyfold/internal/routes"
)

type Options struct {
	Mode string // plan.safe or plan.tight
	// noise verdicts needed before a param can be dropped. one sample gives
	// two (drop and mutate), so the default of 2 means "probed on at least
	// one url with both ops agreeing".
	MinEvidence int
	// drop well-known tracking params even when no probe covered them
	TrustTrackers bool
}

// what the probes said about one request part on one route
type tally struct {
	changes, noise, unknown, failed int
	ops                             map[string]string // op -> worst verdict
	detail                          string            // first "changes" detail
	sample                          string
}

func (t *tally) add(r probe.Result, uri string) {
	if t.ops == nil {
		t.ops = map[string]string{}
	}
	switch r.Verdict {
	case probe.Changes:
		t.changes++
		if t.detail == "" {
			t.detail, t.sample = r.Detail, uri
		}
	case probe.Noise:
		t.noise++
	case probe.Unknown:
		t.unknown++
	default:
		t.failed++
	}
	if rank(r.Verdict) > rank(t.ops[r.Op]) {
		t.ops[r.Op] = r.Verdict
	}
}

func rank(v string) int {
	switch v {
	case probe.Changes:
		return 4
	case probe.Unknown:
		return 3
	case probe.Failed:
		return 2
	case probe.Noise:
		return 1
	}
	return 0
}

func (t *tally) total() int { return t.changes + t.noise + t.unknown + t.failed }

func Synthesize(rep *probe.Report, opts Options) *plan.Plan {
	if opts.Mode == "" {
		opts.Mode = plan.Safe
	}
	if opts.MinEvidence <= 0 {
		opts.MinEvidence = 2
	}
	p := &plan.Plan{Version: 1, Generated: time.Now().UTC(), Mode: opts.Mode, Origin: rep.Origin}
	inv := map[string]*routes.Route{}
	if rep.Inv != nil {
		for _, r := range rep.Inv.Routes {
			inv[r.Host+" "+r.Pattern] = r
		}
	}
	for _, rr := range rep.Routes {
		ir := inv[rr.Host+" "+rr.Pattern]
		if ir == nil {
			ir = &routes.Route{Host: rr.Host, Pattern: rr.Pattern}
		}
		p.Routes = append(p.Routes, route(rr, ir, opts))
	}
	if rep.Inv != nil && !rep.Inv.HasHeaders {
		p.Notes = append(p.Notes, "the logs carry no request headers, so header parts of the key can't be simulated")
	}
	return p
}

func route(rr *probe.RouteResult, ir *routes.Route, opts Options) *plan.Route {
	out := &plan.Route{
		Host: rr.Host, Pattern: rr.Pattern, Requests: ir.Requests,
		Cacheable: rr.Cache.Cacheable, Uncacheable: rr.Cache.Why, TTL: rr.Cache.TTL,
		Evidence: map[string]string{}, Values: map[string][]string{},
	}
	parts := map[string]*tally{}
	get := func(k string) *tally {
		if parts[k] == nil {
			parts[k] = &tally{}
		}
		return parts[k]
	}
	for _, s := range rr.Samples {
		if s == nil {
			continue
		}
		if s.Error == "" {
			out.Samples = append(out.Samples, s.URI)
		}
		for _, r := range s.Results {
			key := r.Part + ":" + r.Name
			get(key).add(r, s.URI)
			if r.Op == "same-class" || r.Op == "other-class" {
				get(key+":"+r.Op).add(r, s.URI)
			}
		}
	}
	vary := map[string]bool{}
	for _, v := range rr.Cache.Vary {
		vary[v] = true
	}
	flag := func(level, kind, name, format string, args ...any) {
		out.Flags = append(out.Flags, plan.Flag{Level: level, Kind: kind, Name: name, Detail: fmt.Sprintf(format, args...)})
	}
	if !out.Cacheable {
		// nothing gets cached here, so key advice and poisoning warnings
		// would only be noise in the report
		flag(plan.Info, "uncacheable", "", "origin says %s, the route is left out of the simulation and the configs", out.Uncacheable)
		return out
	}

	queryParams(out, ir, parts, opts, flag)
	headerParts(out, parts, vary, flag)
	cookieParts(out, parts, vary, flag)
	checkCoverage(out, rr, opts.Mode, flag)
	sortFlags(out.Flags)
	return out
}

type flagFn func(level, kind, name, format string, args ...any)

func queryParams(out *plan.Route, ir *routes.Route, parts map[string]*tally, opts Options, flag flagFn) {
	for _, prm := range ir.Params {
		name := prm.Name
		t := parts["query:"+name]
		share := 0.0
		if ir.Requests > 0 {
			share = float64(prm.Requests) / float64(ir.Requests)
		}
		switch {
		case t != nil && t.changes > 0:
			out.Query.Keep = append(out.Query.Keep, name)
			out.Evidence["query:"+name] = t.detail
			if routes.IsTracker(name) {
				flag(plan.High, "unsafe-drop", name, "%s looks like a tracking param but changes the response (%s). a generic strip-the-trackers rule would serve wrong pages here", name, t.detail)
			} else if prm.Distinct > 50 {
				flag(plan.Warn, "unsafe-drop", name, "%s has %d distinct values and splits the cache, but it changes the response (%s) so it has to stay", name, prm.Distinct, t.detail)
			}
		case t != nil && t.noise >= opts.MinEvidence && t.unknown == 0 && t.failed == 0:
			if routes.IsVersionParam(name) {
				out.Query.Keep = append(out.Query.Keep, name)
				out.Evidence["query:"+name] = "kept by name: looks like a deploy cache buster"
				flag(plan.Info, "version-param", name, "%s probed as noise, but it reads like a cache-busting version param. dropping it would keep serving old assets after a deploy, so it stays", name)
				continue
			}
			out.Query.Drop = append(out.Query.Drop, name)
			out.Values[name] = topValues(prm, 5)
		case t == nil && opts.TrustTrackers && routes.IsTracker(name):
			out.Query.Drop = append(out.Query.Drop, name)
			out.Values[name] = topValues(prm, 5)
			flag(plan.Info, "dropped-by-name", name, "%s was never probed, dropped because it is a known tracker", name)
		default:
			out.Query.Unverified = append(out.Query.Unverified, name)
			why := "never probed"
			if t != nil {
				why = fmt.Sprintf("probes inconclusive (%d noise, %d unknown, %d errors)", t.noise, t.unknown, t.failed)
			}
			if share >= 0.01 {
				flag(plan.Warn, "unverified", name, "%s is on %.0f%% of requests but %s, kept in the key", name, share*100, why)
			}
		}
	}

	if t := parts["order:query"]; t != nil {
		switch {
		case t.changes > 0:
			flag(plan.High, "order-matters", "", "reordering the query changed the response (%s). sorting params in the key would merge pages that differ", t.detail)
		case t.noise > 0 && t.unknown == 0:
			out.Query.Sort = true
		}
	}
	sort.Strings(out.Query.Keep)
	sort.Strings(out.Query.Drop)
	sort.Strings(out.Query.Unverified)
}

func headerParts(out *plan.Route, parts map[string]*tally, vary map[string]bool, flag flagFn) {
	noVary := func(h string) string {
		if vary[h] {
			return "the origin sends vary: " + h + ". caches that honour vary are fine, cloudflare doesn't (outside accept-encoding), so there the key has to carry it"
		}
		return "the origin doesn't send vary: " + h + ", so any url-keyed cache is serving the wrong variant to someone right now"
	}
	same := parts["header:accept-language:same-class"]
	other := parts["header:accept-language:other-class"]
	switch {
	case same != nil && same.changes > 0:
		out.Header.Include = append(out.Header.Include, "accept-language")
		out.Evidence["header:accept-language"] = same.detail
		flag(plan.Warn, "raw-header", "accept-language", "the exact accept-language string matters (%s). keying on it raw splits the cache per browser; normalise it at the edge if you can. %s", same.detail, noVary("accept-language"))
	case other != nil && other.changes > 0:
		out.Header.Lang = true
		out.Evidence["header:accept-language"] = other.detail
		flag(plan.High, "vary-header", "accept-language", "the response language follows accept-language (%s). keyed on the primary language only. %s", other.detail, noVary("accept-language"))
	}

	same = parts["header:user-agent:same-class"]
	other = parts["header:user-agent:other-class"]
	switch {
	case same != nil && same.changes > 0:
		out.Header.Include = append(out.Header.Include, "user-agent")
		out.Evidence["header:user-agent"] = same.detail
		flag(plan.High, "raw-header", "user-agent", "two desktop browsers got different responses (%s). keying on the raw user-agent makes this route close to uncacheable", same.detail)
	case other != nil && other.changes > 0:
		out.Header.Device = true
		out.Evidence["header:user-agent"] = other.detail
		flag(plan.Warn, "vary-header", "user-agent", "mobile and desktop get different responses (%s). keyed on device type. %s", other.detail, noVary("user-agent"))
	}

	if t := parts["header:accept"]; t != nil && t.changes > 0 {
		out.Header.Include = append(out.Header.Include, "accept")
		out.Evidence["header:accept"] = t.detail
		flag(plan.Warn, "vary-header", "accept", "content negotiation on accept (%s). raw accept values vary a lot between browsers, bucket them before keying if the cdn allows it. %s", t.detail, noVary("accept"))
	}
	if t := parts["header:origin"]; t != nil && t.changes > 0 {
		out.Header.Include = append(out.Header.Include, "origin")
		out.Evidence["header:origin"] = t.detail
		flag(plan.Warn, "vary-header", "origin", "the response depends on the origin request header (%s), usually cors. %s", t.detail, noVary("origin"))
	}
	if t := parts["header:x-forwarded-host"]; t != nil && t.changes > 0 {
		flag(plan.High, "unkeyed-input", "x-forwarded-host", "the origin reflects x-forwarded-host into the page (%s). if the cdn forwards that header from clients, one request can poison the cached copy for everyone. strip it at the edge rather than adding it to the key", t.detail)
	}
}

func cookieParts(out *plan.Route, parts map[string]*tally, vary map[string]bool, flag flagFn) {
	var names []string
	for k := range parts {
		if n, ok := strings.CutPrefix(k, "cookie:"); ok {
			names = append(names, n)
		}
	}
	sort.Strings(names)
	why := "the origin doesn't send vary: cookie, so any cache keyed on the url mixes these up today"
	if vary["cookie"] {
		why = "the origin does send vary: cookie, which most cdns answer by not caching at all"
	}
	for _, name := range names {
		t := parts["cookie:"+name]
		if t.changes == 0 {
			continue
		}
		out.Evidence["cookie:"+name] = t.detail
		// presence-only needs positive evidence that the value doesn't
		// matter. an "add" probe alone can't tell the two apart.
		if t.ops["mutate"] != probe.Noise {
			out.Cookie.Include = append(out.Cookie.Include, name)
			flag(plan.High, "vary-cookie", name, "cookie %s changes the response (%s). %s", name, t.detail, why)
			continue
		}
		out.Cookie.Presence = append(out.Cookie.Presence, name)
		flag(plan.Warn, "vary-cookie", name, "whether cookie %s is set changes the response (%s), its value doesn't. keyed on presence only", name, t.detail)
	}
}

// checks the key against every difference the prober saw: each part that
// changed a response must be represented. a gap here is either a bug or an
// input that should be stripped instead of keyed (x-forwarded-host).
func checkCoverage(out *plan.Route, rr *probe.RouteResult, mode string, flag flagFn) {
	missing := map[string]bool{}
	for _, s := range rr.Samples {
		if s == nil {
			continue
		}
		for _, r := range s.Results {
			if r.Verdict != probe.Changes || Covers(out, mode, r) {
				continue
			}
			missing[r.Part+":"+r.Name] = true
		}
	}
	for k := range missing {
		if k == "header:x-forwarded-host" {
			continue // flagged as unkeyed input already
		}
		flag(plan.High, "uncovered", k, "%s changed a response but the key doesn't include it", k)
	}
}

// reports whether the plan's key would tell apart the baseline request and
// the variant behind a probe result.
func Covers(r *plan.Route, mode string, res probe.Result) bool {
	switch res.Part {
	case "query":
		return r.KeepsParam(res.Name, mode)
	case "order":
		return !r.Query.Sort
	case "header":
		if slices.Contains(r.Header.Include, res.Name) {
			return true
		}
		switch res.Name {
		case "accept-language":
			return r.Header.Lang && res.Op == "other-class"
		case "user-agent":
			return r.Header.Device && res.Op == "other-class"
		}
		return false
	case "cookie":
		if slices.Contains(r.Cookie.Include, res.Name) {
			return true
		}
		return slices.Contains(r.Cookie.Presence, res.Name) && res.Op != "mutate"
	}
	return false
}

func topValues(p *routes.Param, n int) []string {
	var out []string
	for _, v := range p.Top {
		if v.V == "" {
			continue
		}
		out = append(out, v.V)
		if len(out) == n {
			break
		}
	}
	return out
}

func sortFlags(fs []plan.Flag) {
	lv := map[string]int{plan.High: 0, plan.Warn: 1, plan.Info: 2}
	sort.SliceStable(fs, func(i, j int) bool { return lv[fs[i].Level] < lv[fs[j].Level] })
}
