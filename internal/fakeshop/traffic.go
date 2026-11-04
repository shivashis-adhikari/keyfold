package fakeshop

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"math/rand/v2"
	"sort"
	"strconv"
	"strings"
	"time"
)

type TrafficOptions struct {
	Requests int
	Start    time.Time
	Span     time.Duration
	Seed     uint64
	// nginx (combined), caddy or cloudflare
	Format string
}

// zipf over [0, n) with exponent s. math/rand's version needs s > 1, and
// real popularity curves for product catalogues sit a bit under that.
type zipf struct{ cdf []float64 }

func newZipf(n int, s float64) *zipf {
	z := &zipf{cdf: make([]float64, n)}
	sum := 0.0
	for i := 0; i < n; i++ {
		sum += 1 / math.Pow(float64(i+1), s)
		z.cdf[i] = sum
	}
	for i := range z.cdf {
		z.cdf[i] /= sum
	}
	return z
}

func (z *zipf) draw(r *rand.Rand) int {
	return sort.SearchFloat64s(z.cdf, r.Float64())
}

var (
	desktopUAs = []string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15",
		"Mozilla/5.0 (X11; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0",
	}
	mobileUAs = []string{
		"Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1",
		"Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Mobile Safari/537.36",
	}
	botUAs    = []string{"Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)", "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)"}
	languages = []string{"en-US,en;q=0.9", "en-US,en;q=0.9", "en-GB,en;q=0.8", "en", "en-US,en;q=0.9", "en-US,en;q=0.5", "en-US,en;q=0.9",
		"de-DE,de;q=0.9,en;q=0.8", "de", "fr-FR,fr;q=0.9,en-US;q=0.8"}
	sources    = []string{"newsletter", "facebook", "instagram", "google", "tiktok", "partner", "affiliate"}
	mediums    = []string{"email", "social", "cpc", "referral"}
	refs       = []string{"homepage", "footer", "blog", "app", "partner-widget"}
	htmlAccept = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
)

type genReq struct {
	t       time.Time
	path    string
	params  [][2]string
	status  int
	bytes   int64
	ua      string
	lang    string
	accept  string
	referer string
	cookies map[string]string
	ttl     time.Duration
	private bool
}

type gen struct {
	r        *rand.Rand
	products *zipf
	terms    *zipf
	items    *zipf
	images   *zipf
	opts     TrafficOptions
	campaign []string
	seen     map[string]time.Time
	i        int
}

// writes a synthetic access log for the shop. the same options
// always produce the same log.
func WriteTraffic(w io.Writer, opts TrafficOptions) error {
	if opts.Requests <= 0 {
		opts.Requests = 100000
	}
	if opts.Start.IsZero() {
		opts.Start = time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	}
	if opts.Span <= 0 {
		opts.Span = 24 * time.Hour
	}
	if opts.Seed == 0 {
		opts.Seed = 42
	}
	g := &gen{
		r:        rand.New(rand.NewPCG(opts.Seed, opts.Seed*31+7)),
		products: newZipf(NumProducts, 0.9),
		terms:    newZipf(len(searchTerms), 1.0),
		items:    newZipf(5000, 0.95),
		images:   newZipf(len(imageNames), 0.9),
		opts:     opts,
		seen:     map[string]time.Time{},
	}
	for i := 0; i < 300; i++ {
		g.campaign = append(g.campaign, fmt.Sprintf("%s_%d", []string{"spring", "summer", "fall", "bf", "xmas", "launch"}[i%6], 2020+i%7))
	}
	bw := bufio.NewWriterSize(w, 1<<16)
	step := float64(opts.Span) / float64(opts.Requests)
	t := opts.Start
	for g.i = 0; g.i < opts.Requests; g.i++ {
		// exponential gaps around the mean rate
		t = t.Add(time.Duration(g.r.ExpFloat64() * step))
		req := g.next(t)
		if err := g.write(bw, req); err != nil {
			return err
		}
	}
	return bw.Flush()
}

func (g *gen) pick(xs []string) string { return xs[g.r.IntN(len(xs))] }

func (g *gen) chance(p float64) bool { return g.r.Float64() < p }

func (g *gen) clickID(n int) string {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-"
	b := make([]byte, n)
	for i := range b {
		b[i] = alphabet[g.r.IntN(len(alphabet))]
	}
	return string(b)
}

// tracking junk that rides along on marketing traffic
func (g *gen) tracking(params [][2]string, scale float64) ([][2]string, string) {
	referer := ""
	if g.chance(0.32 * scale) {
		src := g.pick(sources)
		params = append(params,
			[2]string{"utm_source", src},
			[2]string{"utm_medium", g.pick(mediums)},
			[2]string{"utm_campaign", g.campaign[g.r.IntN(len(g.campaign))]})
		if g.chance(0.3) {
			params = append(params, [2]string{"utm_content", "v" + strconv.Itoa(g.r.IntN(12))})
		}
		referer = "https://" + src + ".com/"
	}
	if g.chance(0.11 * scale) {
		params = append(params, [2]string{"fbclid", "IwAR" + g.clickID(40)})
		referer = "https://m.facebook.com/"
	}
	if g.chance(0.06 * scale) {
		params = append(params, [2]string{"gclid", "Cj0KCQ" + g.clickID(60)})
		referer = "https://www.google.com/"
	}
	if g.chance(0.03 * scale) {
		params = append(params, [2]string{"ref", g.pick(refs)})
	}
	return params, referer
}

func (g *gen) next(t time.Time) genReq {
	req := genReq{t: t, status: 200, accept: htmlAccept}
	switch roll := g.r.Float64(); {
	case roll < 0.05:
		req.ua = g.pick(botUAs)
		req.lang = "en"
	case roll < 0.40:
		req.ua = g.pick(mobileUAs)
	default:
		req.ua = g.pick(desktopUAs)
	}
	if req.lang == "" {
		req.lang = g.pick(languages)
	}
	if g.chance(0.28) {
		req.cookies = map[string]string{"currency": []string{"EUR", "GBP", "USD"}[g.r.IntN(3)]}
	}
	if g.chance(0.25) {
		if req.cookies == nil {
			req.cookies = map[string]string{}
		}
		req.cookies["sessionid"] = g.clickID(24)
	}

	var params [][2]string
	switch roll := g.r.Float64(); {
	case roll < 0.44:
		id := g.products.draw(g.r)
		req.path = "/products/" + ProductSlug(id)
		if g.chance(0.4) {
			params = append(params, [2]string{"color", Colors[min(g.r.IntN(len(Colors)+2), len(Colors)-1)]})
		}
		if g.chance(0.2) {
			params = append(params, [2]string{"size", g.pick(Sizes)})
		}
		params, req.referer = g.tracking(params, 1)
		req.bytes = 38000 + int64(h32(req.path)%52000) + int64(len(req.lang))*7
		req.ttl = 300 * time.Second
	case roll < 0.52:
		req.path = "/"
		params, req.referer = g.tracking(params, 1.4)
		req.bytes = 71000 + int64(g.r.IntN(400))
		req.ttl = 60 * time.Second
	case roll < 0.58:
		id := g.products.draw(g.r)
		req.path = "/products/" + ProductSlug(id) + "/reviews"
		if g.chance(0.5) {
			params = append(params, [2]string{"page", strconv.Itoa(1 + int(g.r.ExpFloat64()*1.2))})
		}
		if g.chance(0.25) {
			params = append(params, [2]string{"sort", "newest"})
		}
		params, req.referer = g.tracking(params, 0.3)
		req.bytes = 14000 + int64(h32(req.path)%9000)
		req.ttl = 120 * time.Second
	case roll < 0.68:
		req.path = "/search"
		params = append(params, [2]string{"q", searchTerms[g.terms.draw(g.r)]})
		if g.chance(0.35) {
			params = append(params, [2]string{"page", strconv.Itoa(2 + int(g.r.ExpFloat64()))})
		}
		if g.chance(0.2) {
			params = append(params, [2]string{"sort", "price"})
		}
		if g.chance(0.002) {
			params = append(params, [2]string{"debug", "1"})
		}
		params, req.referer = g.tracking(params, 0.4)
		req.bytes = 26000 + int64(g.r.IntN(30000))
		req.ttl = 30 * time.Second
	case roll < 0.80:
		id := 1 + g.items.draw(g.r)
		req.path = "/api/v1/items/" + strconv.Itoa(id)
		req.accept = "application/json, text/javascript, */*; q=0.01"
		if g.chance(0.2) {
			params = append(params, [2]string{"fields", []string{"id,name,price", "id,stock"}[g.r.IntN(2)]})
		}
		if g.chance(0.02) {
			params = append(params, [2]string{"callback", "jQuery3510" + strconv.Itoa(g.r.IntN(1e6))})
		}
		// jquery's cache: false appends a millisecond timestamp
		if g.chance(0.55) {
			params = append(params, [2]string{"_", strconv.FormatInt(t.UnixMilli()-int64(g.r.IntN(5000)), 10)})
		}
		req.bytes = 900 + int64(h32(req.path)%4000)
		req.ttl = 60 * time.Second
	case roll < 0.90:
		build := Builds[0]
		if g.i > g.opts.Requests/2 {
			build = Builds[1]
		}
		ext := "js"
		if g.chance(0.35) {
			ext = "css"
		}
		name := assets[g.r.IntN(len(assets))]
		req.path = AssetPath(name, build, ext)
		req.accept = "*/*"
		if g.chance(0.6) {
			params = append(params, [2]string{"v", build[:6]})
		}
		req.bytes = 20000 + int64(h32(req.path)%380000)
		req.ttl = 365 * 24 * time.Hour
	case roll < 0.985:
		name := imageNames[g.images.draw(g.r)]
		req.path = "/img/" + name + ".jpg"
		req.accept = "image/avif,image/webp,image/apng,image/*,*/*;q=0.8"
		params = append(params, [2]string{"w", []string{"320", "640", "1280"}[g.r.IntN(3)]})
		if g.chance(0.3) {
			params = append(params, [2]string{"q", "75"})
		}
		params, _ = g.tracking(params, 0.1)
		req.bytes = 15000 + int64(h32(req.path)%280000)
		req.ttl = 24 * time.Hour
	default:
		req.path = "/account"
		req.private = true
		req.bytes = 9000 + int64(g.r.IntN(800))
	}
	if g.chance(0.004) {
		// dead links from old campaigns
		req.path = "/products/discontinued-thing-" + strconv.Itoa(g.r.IntN(50))
		req.status = 404
		req.bytes = 15
		req.ttl = 60 * time.Second
		req.private = false
		params, req.referer = g.tracking(nil, 1)
	}
	// people paste links, apps rebuild them, a fair share arrives with the
	// params in some other order
	if len(params) > 1 && g.chance(0.3) {
		g.r.Shuffle(len(params), func(i, j int) { params[i], params[j] = params[j], params[i] })
	}
	req.params = params
	return req
}

func (r *genReq) uri() string {
	if len(r.params) == 0 {
		return r.path
	}
	var b strings.Builder
	b.WriteString(r.path)
	for i, p := range r.params {
		if i == 0 {
			b.WriteByte('?')
		} else {
			b.WriteByte('&')
		}
		b.WriteString(escapeQuery(p[0]))
		b.WriteByte('=')
		b.WriteString(escapeQuery(p[1]))
	}
	return b.String()
}

func escapeQuery(s string) string {
	return strings.NewReplacer(" ", "+", "&", "%26", "=", "%3D", "#", "%23", ",", "%2C").Replace(s)
}

// what a cdn keyed on the full url would have reported
func (g *gen) cacheStatus(r *genReq) string {
	if r.private {
		return "dynamic"
	}
	u := r.uri()
	last, ok := g.seen[u]
	g.seen[u] = r.t
	switch {
	case !ok:
		return "miss"
	case r.t.Sub(last) > r.ttl:
		return "expired"
	}
	return "hit"
}

func (g *gen) write(w *bufio.Writer, r genReq) error {
	status := g.cacheStatus(&r)
	ip := fmt.Sprintf("%d.%d.%d.%d", 100+g.r.IntN(100), g.r.IntN(256), g.r.IntN(256), 1+g.r.IntN(254))
	switch g.opts.Format {
	case "", "nginx":
		ref := r.referer
		if ref == "" {
			ref = "-"
		}
		_, err := fmt.Fprintf(w, "%s - - [%s] \"GET %s HTTP/1.1\" %d %d \"%s\" \"%s\"\n",
			ip, r.t.Format("02/Jan/2006:15:04:05 -0700"), r.uri(), r.status, r.bytes, ref, r.ua)
		return err
	case "caddy":
		headers := map[string][]string{
			"User-Agent":      {r.ua},
			"Accept":          {r.accept},
			"Accept-Language": {r.lang},
			"Accept-Encoding": {"gzip, deflate, br"},
		}
		if r.referer != "" {
			headers["Referer"] = []string{r.referer}
		}
		if len(r.cookies) > 0 {
			headers["Cookie"] = []string{"REDACTED"}
		}
		line := map[string]any{
			"level": "info", "ts": float64(r.t.UnixNano()) / 1e9, "logger": "http.log.access.log0", "msg": "handled request",
			"request": map[string]any{
				"remote_ip": ip, "remote_port": strconv.Itoa(30000 + g.r.IntN(30000)), "client_ip": ip,
				"proto": "HTTP/2.0", "method": "GET", "host": Host, "uri": r.uri(), "headers": headers,
				"tls": map[string]any{"resumed": false, "version": 772, "cipher_suite": 4865, "proto": "h2", "server_name": Host},
			},
			"bytes_read": 0, "user_id": "", "duration": 0.002 + g.r.Float64()*0.05,
			"size": r.bytes, "status": r.status,
			"resp_headers": map[string][]string{"Server": {"Caddy"}, "Content-Type": {"text/html; charset=utf-8"}},
		}
		return writeJSONLine(w, line)
	case "cloudflare":
		line := map[string]any{
			"CacheCacheStatus":       status,
			"ClientIP":               ip,
			"ClientRequestHost":      Host,
			"ClientRequestMethod":    "GET",
			"ClientRequestURI":       r.uri(),
			"ClientRequestScheme":    "https",
			"ClientRequestUserAgent": r.ua,
			"ClientRequestReferer":   r.referer,
			"EdgeResponseBodyBytes":  r.bytes,
			"EdgeResponseBytes":      r.bytes + 620,
			"EdgeResponseStatus":     r.status,
			"EdgeStartTimestamp":     r.t.UnixNano(),
			"RayID":                  fmt.Sprintf("%016x", g.r.Uint64()),
			"RequestHeaders":         map[string]string{"accept-language": r.lang, "accept": r.accept},
		}
		// logpush only records cookies you list in the job's custom fields.
		// a sane setup lists currency and not the session.
		if c, ok := r.cookies["currency"]; ok {
			line["Cookies"] = map[string]string{"currency": c}
		}
		return writeJSONLine(w, line)
	}
	return fmt.Errorf("unknown traffic format %q", g.opts.Format)
}

func writeJSONLine(w *bufio.Writer, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	w.Write(b)
	return w.WriteByte('\n')
}
