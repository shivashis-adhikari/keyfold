package gen

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/shivashis-adhikari/keyfold/internal/plan"
	"github.com/shivashis-adhikari/keyfold/internal/routes"
)

// the body of a rulesets api call. one per phase:
//
//	put /zones/{zone_id}/rulesets/phases/{phase}/entrypoint
//
// put replaces every rule in that phase, so merge with existing rules
// first if the zone has any.
type cfRuleset struct {
	Description string   `json:"description"`
	Rules       []cfRule `json:"rules"`
}

type cfRule struct {
	Ref              string         `json:"ref"`
	Description      string         `json:"description"`
	Expression       string         `json:"expression"`
	Action           string         `json:"action"`
	ActionParameters map[string]any `json:"action_parameters"`
	Enabled          bool           `json:"enabled"`
}

// returns a json object keyed by ruleset phase, plus warnings
// about things the chosen plan tier can't express.
func Cloudflare(p *plan.Plan, opts Options) ([]byte, []string, error) {
	tier := strings.ToLower(opts.CFPlan)
	if tier == "" {
		tier = "enterprise"
	}
	switch tier {
	case "free", "pro", "business", "enterprise":
	default:
		return nil, nil, fmt.Errorf("cloudflare plan %q, want free, pro, business or enterprise", opts.CFPlan)
	}
	ent := tier == "enterprise"
	regex := opts.CFRegex
	if regex && tier != "business" && !ent {
		return nil, nil, fmt.Errorf("the regex operator needs a business or enterprise plan, not %s", tier)
	}
	var warns []string
	cache := cfRuleset{Description: "keyfold cache keys"}
	for _, r := range routesToEmit(p) {
		key, w := cfCacheKey(r, p.Mode, ent, opts.Canary)
		warns = append(warns, w...)
		if key == nil {
			continue
		}
		expr := cfExpression(r, regex)
		if opts.Canary {
			expr += fmt.Sprintf(` and any(http.request.headers[%q][*] eq "1")`, strings.ToLower(CanaryHeader))
		}
		cache.Rules = append(cache.Rules, cfRule{
			Ref:              "keyfold_" + slug(r.Host+" "+r.Pattern),
			Description:      "keyfold: " + strings.TrimSpace(r.Host+" "+r.Pattern),
			Expression:       expr,
			Action:           "set_cache_settings",
			ActionParameters: map[string]any{"cache": true, "cache_key": key},
			Enabled:          true,
		})
	}
	if opts.Canary && !ent {
		warns = append(warns, "canary rules can't put the canary header in the key below enterprise, so canary requests share cache entries with normal traffic for the same planned key")
	}

	out := map[string]cfRuleset{"http_request_cache_settings": cache}
	if hit := reflectsForwardedHost(p); len(hit) > 0 {
		var hosts []string
		seen := map[string]bool{}
		for _, r := range hit {
			if r.Host != "" && !seen[r.Host] {
				seen[r.Host] = true
				hosts = append(hosts, strconv.Quote(r.Host))
			}
		}
		expr := "true"
		if len(hosts) > 0 {
			expr = "http.host in {" + strings.Join(hosts, " ") + "}"
		}
		out["http_request_late_transform"] = cfRuleset{
			Description: "keyfold: strip client-sent x-forwarded-host",
			Rules: []cfRule{{
				Ref:         "keyfold_strip_x_forwarded_host",
				Description: "the origin reflects x-forwarded-host into cached pages",
				Expression:  expr,
				Action:      "rewrite",
				ActionParameters: map[string]any{
					"headers": map[string]any{"x-forwarded-host": map[string]string{"operation": "remove"}},
				},
				Enabled: true,
			}},
		}
	}
	b, err := json.MarshalIndent(out, "", "  ")
	return append(b, '\n'), warns, err
}

// path condition. wildcard's '*' also matches '/', so a second wildcard
// with one more slash than the pattern has rules out deeper paths: a path
// with exactly n slashes can only line up with a pattern of n slashes one
// segment at a time.
func cfExpression(r *plan.Route, regex bool) string {
	var parts []string
	if r.Host != "" {
		parts = append(parts, fmt.Sprintf("http.host eq %q", r.Host))
	}
	switch {
	case !routes.HasPlaceholder(r.Pattern):
		parts = append(parts, fmt.Sprintf("http.request.uri.path eq %q", r.Pattern))
	case regex:
		parts = append(parts, fmt.Sprintf("http.request.uri.path matches %q", routes.Regex(r.Pattern)))
	default:
		guard := strings.Repeat("/*", routes.SegmentCount(r.Pattern)+1)
		parts = append(parts,
			fmt.Sprintf("http.request.uri.path strict wildcard %q", routes.Wildcard(r.Pattern)),
			fmt.Sprintf("not http.request.uri.path strict wildcard %q", guard))
	}
	return "(" + strings.Join(parts, " and ") + ")"
}

func cfCacheKey(r *plan.Route, mode string, ent, canary bool) (map[string]any, []string) {
	var warns []string
	name := strings.TrimSpace(r.Host + " " + r.Pattern)
	key := map[string]any{}
	if r.Query.Sort {
		key["ignore_query_strings_order"] = true
	}
	needsHeaders := r.Header.Lang || r.Header.Device || len(r.Header.Include) > 0
	needsCookies := len(r.Cookie.Include) > 0 || len(r.Cookie.Presence) > 0
	keepNothing := len(r.Query.Keep)+len(r.Query.Unverified) == 0

	if !ent {
		// below enterprise the only query option is ignoring it entirely,
		// and no header or cookie parts exist. a key that leaves out a
		// part the probe saw change the page is worse than no rule.
		if needsHeaders || needsCookies {
			warns = append(warns, fmt.Sprintf("%s: needs header or cookie parts in the key, only enterprise has those; no rule written", name))
			return nil, warns
		}
		if len(r.Query.Drop) > 0 {
			if keepNothing && mode == plan.Tight {
				key["custom_key"] = map[string]any{"query_string": map[string]any{"exclude": map[string]any{"all": true}}}
			} else {
				warns = append(warns, fmt.Sprintf("%s: dropping %s while keeping other params needs enterprise custom keys, only the param order setting is written", name, strings.Join(r.Query.Drop, ", ")))
			}
		}
		if len(key) == 0 {
			return nil, warns
		}
		return key, warns
	}

	custom := map[string]any{}
	switch {
	case mode == plan.Tight && keepNothing:
		custom["query_string"] = map[string]any{"exclude": map[string]any{"all": true}}
	case mode == plan.Tight:
		custom["query_string"] = map[string]any{"include": map[string]any{"list": kept(r)}}
	case len(r.Query.Drop) > 0:
		custom["query_string"] = map[string]any{"exclude": map[string]any{"list": r.Query.Drop}}
	}
	headers := append([]string(nil), r.Header.Include...)
	if canary {
		headers = append(headers, strings.ToLower(CanaryHeader))
	}
	if len(headers) > 0 {
		custom["header"] = map[string]any{"include": headers}
	}
	if r.Header.Lang || r.Header.Device {
		custom["user"] = map[string]any{"lang": r.Header.Lang, "device_type": r.Header.Device}
	}
	if needsCookies {
		c := map[string]any{}
		if len(r.Cookie.Include) > 0 {
			c["include"] = r.Cookie.Include
		}
		if len(r.Cookie.Presence) > 0 {
			c["check_presence"] = r.Cookie.Presence
		}
		custom["cookie"] = c
	}
	if len(custom) > 0 {
		key["custom_key"] = custom
	}
	if len(key) == 0 {
		return nil, warns
	}
	return key, warns
}
