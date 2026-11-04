package routes

import (
	"net/url"
	"regexp"
	"strings"
)

// one name=value pair from a raw query string, in the order it was sent.
type Pair struct {
	Name  string // decoded
	Value string // decoded
	Raw   string // exactly as it appeared, used when rebuilding keys
}

// splits a raw query without normalising it. the stdlib query parser would lose the
// original order and encoding, and both matter for cache keys: cdns compare
// the bytes, not the meaning.
func SplitQuery(raw string) []Pair {
	if raw == "" {
		return nil
	}
	out := make([]Pair, 0, strings.Count(raw, "&")+1)
	for len(raw) > 0 {
		var part string
		part, raw, _ = strings.Cut(raw, "&")
		if part == "" {
			continue
		}
		name, value, _ := strings.Cut(part, "=")
		out = append(out, Pair{Name: unescape(name), Value: unescape(value), Raw: part})
	}
	return out
}

func unescape(s string) string {
	if !strings.ContainsAny(s, "%+") {
		return s
	}
	if u, err := url.QueryUnescape(s); err == nil {
		return u
	}
	return s
}

// cookie names that look like credentials. their values never get copied
// into reports or replayed by the prober.
var sensitiveRe = regexp.MustCompile(`(?i)(sess|sid$|^sid|auth|token|jwt|login|remember|csrf|xsrf|secret|passw|apikey|api_key|bearer|^_?ga$|^_gid$|^__cf|^cf_)`)

// reports whether a cookie or param name probably carries a
// credential or a per-user id.
func IsSensitive(name string) bool { return sensitiveRe.MatchString(name) }

// tracking params that never change what an origin renders, as far as any
// site i've looked at goes. this list is only a hint: keyfold still wants
// probe evidence before dropping one, unless told to trust the list.
var trackers = map[string]bool{
	"utm_source": true, "utm_medium": true, "utm_campaign": true, "utm_term": true,
	"utm_content": true, "utm_id": true, "utm_name": true,
	"gclid": true, "gbraid": true, "wbraid": true, "dclid": true, "gclsrc": true,
	"fbclid": true, "msclkid": true, "yclid": true, "ttclid": true, "twclid": true,
	"li_fat_id": true, "igshid": true, "mc_cid": true, "mc_eid": true,
	"_hsenc": true, "_hsmi": true, "mkt_tok": true, "srsltid": true, "_ga": true, "_gl": true,
}

// reports whether the param name is a well known click or campaign
// tracker.
func IsTracker(name string) bool {
	n := strings.ToLower(name)
	return trackers[n] || strings.HasPrefix(n, "utm_")
}

// catches ?v=, ?ver= and friends. these are how people bust
// caches after a deploy. at any single moment the origin ignores them, so a
// probe calls them noise, but dropping one from the key means serving last
// week's css after the next release.
func IsVersionParam(name string) bool {
	switch strings.ToLower(name) {
	case "v", "ver", "version", "rev", "build", "hash", "cb", "cachebust", "cache_bust", "cachebuster", "bust":
		return true
	}
	return false
}
