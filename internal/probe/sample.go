package probe

import (
	"context"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"sort"
	"strconv"
	"strings"

	"github.com/shivashis-adhikari/keyfold/internal/normalize"
	"github.com/shivashis-adhikari/keyfold/internal/routes"
)

// one request to send: path, query pairs in order, headers and cookies.
type spec struct {
	host    string
	path    string
	pairs   []routes.Pair
	header  http.Header
	cookies [][2]string
}

func (s spec) clone() spec {
	c := s
	c.pairs = append([]routes.Pair(nil), s.pairs...)
	c.header = s.header.Clone()
	c.cookies = append([][2]string(nil), s.cookies...)
	return c
}

func (s spec) uri() string {
	if len(s.pairs) == 0 {
		return s.path
	}
	raw := make([]string, len(s.pairs))
	for i, p := range s.pairs {
		raw[i] = p.Raw
	}
	return s.path + "?" + strings.Join(raw, "&")
}

type fetched struct {
	fp     normalize.Fingerprint
	tokens normalize.Tokens
	header http.Header
	err    error
}

func (p *prober) fetch(ctx context.Context, s spec) fetched {
	select {
	case <-p.tick.C:
	case <-ctx.Done():
		return fetched{err: ctx.Err()}
	}
	uri := s.uri()
	if p.opts.CacheBuster != "" {
		p.mu.Lock()
		p.buster++
		n := p.buster
		p.mu.Unlock()
		sep := "?"
		if strings.Contains(uri, "?") {
			sep = "&"
		}
		uri += sep + p.opts.CacheBuster + "=" + strconv.Itoa(n) + strconv.FormatUint(rand.Uint64()%1e6, 36)
	}
	o := p.opts.Origin
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, o.Scheme+"://"+o.Host+uri, nil)
	if err != nil {
		return fetched{err: err}
	}
	req.Header = s.header.Clone()
	req.Header.Del("Accept-Encoding") // let the transport do gzip and decode it
	if len(s.cookies) > 0 {
		parts := make([]string, len(s.cookies))
		for i, c := range s.cookies {
			parts[i] = c[0] + "=" + c[1]
		}
		req.Header.Set("Cookie", strings.Join(parts, "; "))
	}
	req.Host = s.host

	p.mu.Lock()
	p.sent++
	p.mu.Unlock()
	resp, err := p.client.Do(req)
	if err != nil {
		return fetched{err: err}
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, p.opts.MaxBody))
	if err != nil {
		return fetched{err: err}
	}
	if p.opts.CacheBuster != "" {
		// a redirect that echoes the buster back would differ every time
		if loc := resp.Header.Get("Location"); loc != "" {
			resp.Header.Set("Location", stripParam(loc, p.opts.CacheBuster))
		}
	}
	fp, norm := p.opts.Normalizer.Fingerprint(resp.Header, resp.StatusCode, body)
	return fetched{fp: fp, tokens: normalize.Tokenize(norm), header: resp.Header}
}

func stripParam(u, name string) string {
	base, q, ok := strings.Cut(u, "?")
	if !ok {
		return u
	}
	var keep []string
	for _, p := range routes.SplitQuery(q) {
		if p.Name != name {
			keep = append(keep, p.Raw)
		}
	}
	if len(keep) == 0 {
		return base
	}
	return base + "?" + strings.Join(keep, "&")
}

// the baselines for one url, and the noise learned from them.
type baseline struct {
	fps    []normalize.Fingerprint
	vol    normalize.Volatile
	flappy bool // status or headers changed between identical requests
}

func (b *baseline) add(f fetched) {
	if len(b.fps) > 0 && !f.fp.SameMeta(b.fps[0]) {
		b.flappy = true
	}
	b.fps = append(b.fps, f.fp)
	b.vol.Add(f.tokens)
}

func (b *baseline) stable() bool {
	if b.flappy {
		return false
	}
	for _, fp := range b.fps[1:] {
		if fp.Body != b.fps[0].Body {
			return false
		}
	}
	return true
}

// compares one variant against the baselines. confirm says the verdict is a
// difference that should be double-checked before anyone believes it.
func (b *baseline) judge(v fetched) (verdict, detail string, confirm bool) {
	if v.err != nil {
		return Failed, v.err.Error(), false
	}
	if !v.fp.SameMeta(b.fps[0]) {
		if b.flappy {
			return Unknown, "baseline headers are unstable: " + v.fp.Diff(b.fps[0]), false
		}
		return Changes, v.fp.Diff(b.fps[0]), true
	}
	if b.stable() && v.fp.Body == b.fps[0].Body {
		return Noise, "", false
	}
	res := b.vol.Residual(v.tokens, 6)
	if len(res) == 0 {
		return Noise, "differs only where the baselines differ", false
	}
	return Changes, "body differs: " + strings.Join(res, " "), true
}

type variant struct {
	part, name, op, value string
	s                     spec
}

// browser-ish defaults for the baseline. most origins behave differently
// for curl's user agent, and that isn't what real traffic sees.
const (
	desktopUA  = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36"
	desktopUA2 = "Mozilla/5.0 (X11; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0"
	mobileUA   = "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1"
	mobileUA2  = "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Mobile Safari/537.36"
	htmlAccept = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
	imgAccept  = "image/avif,image/webp,image/apng,image/*,*/*;q=0.8"
)

func isImagePattern(p string) bool {
	for _, ext := range []string{".jpg", ".jpeg", ".png", ".gif", ".webp", ".avif", ".svg"} {
		if strings.HasSuffix(strings.ToLower(p), ext) {
			return true
		}
	}
	return false
}

func isMobileUA(ua string) bool {
	ua = strings.ToLower(ua)
	return strings.Contains(ua, "mobile") || strings.Contains(ua, "iphone") || strings.Contains(ua, "android")
}

func (p *prober) baseSpec(r *routes.Route, smp routes.Sample) spec {
	host := p.opts.HostHeader
	if host == "" {
		host = r.Host
	}
	if host == "" {
		host = p.opts.Origin.Host
	}
	h := http.Header{}
	h.Set("User-Agent", desktopUA)
	h.Set("Accept-Language", "en-US,en;q=0.9")
	if isImagePattern(r.Pattern) {
		h.Set("Accept", imgAccept)
	} else {
		h.Set("Accept", htmlAccept)
	}
	for k, v := range smp.Header {
		h.Set(k, v)
	}
	for k, vs := range p.opts.Header {
		h[http.CanonicalHeaderKey(k)] = vs
	}
	s := spec{host: host, path: pathOf(smp.URI), pairs: routes.SplitQuery(queryOf(smp.URI)), header: h}
	names := make([]string, 0, len(smp.Cookies))
	for k := range smp.Cookies {
		names = append(names, k)
	}
	sort.Strings(names)
	for _, k := range names {
		s.cookies = append(s.cookies, [2]string{k, smp.Cookies[k]})
	}
	for k, v := range p.opts.Cookies {
		s.cookies = setCookie(s.cookies, k, v)
	}
	return s
}

func setCookie(cs [][2]string, name, value string) [][2]string {
	for i := range cs {
		if cs[i][0] == name {
			cs[i][1] = value
			return cs
		}
	}
	return append(cs, [2]string{name, value})
}

// picks a value to swap in. a real value from the logs beats a made-up one:
// made-up values tend to hit validation and 404, and then everything looks
// like it matters.
func alternative(cur string, stats *routes.Param) string {
	if stats != nil {
		for _, v := range stats.Top {
			if v.V != cur && v.V != "" {
				return v.V
			}
		}
	}
	if n, err := strconv.Atoi(cur); err == nil {
		if n == 1 {
			return "2"
		}
		return strconv.Itoa(n + 1)
	}
	switch strings.ToLower(cur) {
	case "true":
		return "false"
	case "false":
		return "true"
	case "yes":
		return "no"
	case "no":
		return "yes"
	case "":
		return "1"
	}
	return cur + "x"
}

func (p *prober) variants(r *routes.Route, base spec, headers bool) []variant {
	var vs []variant
	for i, pair := range base.pairs {
		if pair.Name == p.opts.CacheBuster && pair.Name != "" {
			continue
		}
		drop := base.clone()
		drop.pairs = append(drop.pairs[:i], drop.pairs[i+1:]...)
		vs = append(vs, variant{"query", pair.Name, "drop", "", drop})

		alt := alternative(pair.Value, r.Param(pair.Name))
		mut := base.clone()
		mut.pairs[i] = routes.Pair{Name: pair.Name, Value: alt, Raw: escapeRaw(pair, alt)}
		vs = append(vs, variant{"query", pair.Name, "mutate", alt, mut})
	}
	if names := distinctNames(base.pairs); len(names) > 1 {
		rev := base.clone()
		for i, j := 0, len(rev.pairs)-1; i < j; i, j = i+1, j-1 {
			rev.pairs[i], rev.pairs[j] = rev.pairs[j], rev.pairs[i]
		}
		vs = append(vs, variant{"order", "query", "reorder", "", rev})
	}

	have := map[string]bool{}
	for i, c := range base.cookies {
		have[c[0]] = true
		drop := base.clone()
		drop.cookies = append(drop.cookies[:i], drop.cookies[i+1:]...)
		vs = append(vs, variant{"cookie", c[0], "drop", "", drop})
		alt := alternative(c[1], r.Cookie(c[0]))
		mut := base.clone()
		mut.cookies[i][1] = alt
		vs = append(vs, variant{"cookie", c[0], "mutate", alt, mut})
	}
	// cookies seen in the logs for this route but not on this sample: try
	// adding them with a real value
	for _, c := range r.Cookies {
		if have[c.Name] || routes.IsSensitive(c.Name) || len(c.Top) == 0 || c.Top[0].V == "" {
			continue
		}
		add := base.clone()
		add.cookies = append(add.cookies, [2]string{c.Name, c.Top[0].V})
		vs = append(vs, variant{"cookie", c.Name, "add", c.Top[0].V, add})
	}

	if !headers {
		return vs
	}
	set := func(name, op, value string) {
		s := base.clone()
		if value == "" {
			s.header.Del(name)
		} else {
			s.header.Set(name, value)
		}
		vs = append(vs, variant{"header", strings.ToLower(name), op, value, s})
	}
	// same-class swaps a value for one any sane key would treat alike;
	// other-class crosses the line a cdn's normalised key draws (primary
	// language, device type). the pair tells raw-header variance apart from
	// variance a cdn can key on cheaply.
	lang := routes.FirstLanguage(base.header.Get("Accept-Language"))
	if lang == "" {
		lang = "en"
	}
	same, ok := regional[lang]
	if !ok {
		same = lang + ";q=0.8"
	}
	set("Accept-Language", "same-class", same)
	other := "de-DE,de;q=0.9"
	if lang == "de" {
		other = "fr-FR,fr;q=0.9"
	}
	set("Accept-Language", "other-class", other)

	if isMobileUA(base.header.Get("User-Agent")) {
		set("User-Agent", "same-class", mobileUA2)
		set("User-Agent", "other-class", desktopUA)
	} else {
		set("User-Agent", "same-class", desktopUA2)
		set("User-Agent", "other-class", mobileUA)
	}
	if isImagePattern(r.Pattern) {
		set("Accept", "mutate", "*/*")
	} else {
		set("Accept", "mutate", "application/json")
	}
	// unkeyed inputs: headers a cdn passes through but never keys on. if the
	// origin reflects one, anyone can poison the cached copy.
	set("X-Forwarded-Host", "add", "keyfold-probe.invalid")
	set("Origin", "add", "https://"+base.host)
	return vs
}

// a second spelling of the same primary language, for same-class probes
var regional = map[string]string{
	"en": "en-GB,en;q=0.8", "de": "de-AT,de;q=0.8", "fr": "fr-CA,fr;q=0.8",
	"es": "es-MX,es;q=0.8", "pt": "pt-BR,pt;q=0.8", "it": "it-CH,it;q=0.8",
}

func distinctNames(ps []routes.Pair) []string {
	seen := map[string]bool{}
	var out []string
	for _, p := range ps {
		if !seen[p.Name] {
			seen[p.Name] = true
			out = append(out, p.Name)
		}
	}
	return out
}

// keeps the original name encoding, swaps the value.
func escapeRaw(p routes.Pair, value string) string {
	name, _, _ := strings.Cut(p.Raw, "=")
	return name + "=" + escapeValue(value)
}

func escapeValue(v string) string {
	var b strings.Builder
	for i := 0; i < len(v); i++ {
		c := v[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', strings.IndexByte("-_.~,:", c) >= 0:
			b.WriteByte(c)
		case c == ' ':
			b.WriteByte('+')
		default:
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String()
}

func (p *prober) sample(ctx context.Context, r *routes.Route, smp routes.Sample, headers bool) (*SampleResult, CacheInfo) {
	sr := &SampleResult{URI: smp.URI}
	before := p.count()
	defer func() { sr.Requests = p.count() - before }()

	base := p.baseSpec(r, smp)
	var b baseline
	var ci CacheInfo
	for i := 0; i < p.opts.Baselines; i++ {
		f := p.fetch(ctx, base)
		if f.err != nil {
			sr.Error = f.err.Error()
			return sr, CacheInfo{Why: "baseline request failed: " + f.err.Error()}
		}
		if i == 0 {
			ci = cacheInfo(f.fp.Status, f.header)
		}
		b.add(f)
	}
	sr.Baseline = b.fps[0]

	for _, v := range p.variants(r, base, headers) {
		f := p.fetch(ctx, v.s)
		verdict, detail, confirm := b.judge(f)
		if confirm {
			verdict, detail = p.confirm(ctx, &b, base, v.s, f)
		}
		sr.Results = append(sr.Results, Result{Part: v.part, Name: v.name, Op: v.op, Value: v.value, Verdict: verdict, Detail: detail})
		if ctx.Err() != nil {
			break
		}
	}

	// one more baseline at the end. if it no longer looks like the first
	// ones, the page changed while we were probing (a deploy, a price
	// update) and the "changes" verdicts are suspect.
	if f := p.fetch(ctx, base); f.err == nil {
		if v, _, _ := b.judge(f); v != Noise {
			sr.Drifted = true
		}
	}
	sr.Stable = b.stable()
	sr.Volatile = b.vol.Len()
	return sr, ci
}

// re-checks a difference. the variant is fetched a second time, and
// whatever moves between the two fetches counts as noise as well. then fresh
// baselines go into the noise model, one round at a time, until the
// difference either goes away or has survived enough rounds. pages that were
// already unstable get more rounds, since rotating content needs more
// samples before every variant of it has shown up once.
func (p *prober) confirm(ctx context.Context, b *baseline, base, vs spec, first fetched) (string, string) {
	second := p.fetch(ctx, vs)
	if second.err != nil {
		return Unknown, "confirmation failed: " + second.err.Error()
	}
	b.vol.Learn(first.tokens, second.tokens)
	rounds := 2
	var v1, d1, v2 string
	for i := 0; i < rounds; i++ {
		if f := p.fetch(ctx, base); f.err == nil {
			b.add(f)
		}
		if !b.stable() {
			rounds = 5
		}
		v1, d1, _ = b.judge(first)
		v2, _, _ = b.judge(second)
		if v1 == Noise || v2 == Noise {
			return Noise, "difference did not reproduce"
		}
		if ctx.Err() != nil {
			break
		}
	}
	if v1 == Changes && v2 == Changes {
		return Changes, d1
	}
	return Unknown, d1
}

func (p *prober) count() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.sent
}
