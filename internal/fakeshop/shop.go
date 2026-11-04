// package fakeshop is a small origin with known cache key behaviour, plus a
// traffic generator for it. tests and the demo in the readme run keyfold
// against it, so every quirk here is deliberate and the expected verdicts
// are listed in truth.go.
package fakeshop

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash/fnv"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

const Host = "shop.example.com"

var (
	adjectives = []string{"blue", "red", "quiet", "sturdy", "tiny", "giant", "smart", "classic", "rustic", "silver",
		"golden", "wooden", "electric", "foldable", "vintage", "modern", "compact", "deluxe", "travel", "organic"}
	nouns = []string{"widget", "kettle", "lamp", "backpack", "chair", "mug", "speaker", "notebook", "jacket", "sneaker",
		"blender", "desk", "clock", "umbrella", "wallet", "bottle", "headset", "tent", "scarf", "pan",
		"drone", "router", "keyboard", "monitor", "camera", "stool", "rug", "vase", "candle", "toaster",
		"grinder", "teapot", "hammock", "lantern", "satchel", "poncho", "beanie", "glove", "blanket", "pillow",
		"skillet", "whisk", "ladle", "sieve", "trowel", "shovel", "rake", "hose", "planter", "bench",
		"easel", "palette", "brush", "canvas", "tripod", "lens", "flash", "strap", "case", "stand",
		"puzzle", "kite", "yoyo", "frisbee", "racket", "helmet", "goggles", "paddle", "kayak", "saddle",
		"bell", "pump", "lock", "basket", "rack", "mirror", "shelf", "drawer", "cabinet", "hook",
		"scale", "timer", "thermos", "cooler", "grill", "smoker", "spatula", "tongs", "apron", "mitt",
		"radio", "charger", "cable", "adapter", "dock", "mouse", "stylus", "tablet", "phone", "watch"}
	searchTerms []string
	assets      = []string{"app", "vendor", "checkout", "search", "product", "account", "styles", "print"}
	imageNames  []string
	Colors      = []string{"black", "white", "red", "blue", "green"}
	Sizes       = []string{"xs", "s", "m", "l", "xl"}
)

func init() {
	for _, a := range adjectives {
		for _, n := range nouns {
			searchTerms = append(searchTerms, a+" "+n)
		}
	}
	for i := 0; i < 1500; i++ {
		imageNames = append(imageNames, fmt.Sprintf("%s-%s-%d", adjectives[i%len(adjectives)], nouns[(i/len(adjectives))%len(nouns)], i))
	}
}

// the catalogue size. slugs are adjective-noun-n.
const NumProducts = 2000

func ProductSlug(i int) string {
	return fmt.Sprintf("%s-%s-%d", adjectives[i%len(adjectives)], nouns[(i/len(adjectives))%len(nouns)], i)
}

func productIndex(slug string) (int, bool) {
	j := strings.LastIndexByte(slug, '-')
	if j < 0 {
		return 0, false
	}
	n, err := strconv.Atoi(slug[j+1:])
	if err != nil || n < 0 || n >= NumProducts || ProductSlug(n) != slug {
		return 0, false
	}
	return n, true
}

// two builds of the frontend. the traffic generator switches from the first
// to the second half way through, like a deploy would.
var Builds = []string{"3f9c2a1b", "8e41d07c"}

func AssetPath(name, build, ext string) string { return "/static/" + name + "." + build + "." + ext }

func h32(parts ...string) uint32 {
	h := fnv.New32a()
	for _, p := range parts {
		h.Write([]byte(p))
		h.Write([]byte{0})
	}
	return h.Sum32()
}

// the origin. it is safe for concurrent use.
type Shop struct {
	mux     *http.ServeMux
	counter atomic.Uint64
	now     func() time.Time
}

func New() *Shop {
	s := &Shop{now: time.Now}
	m := http.NewServeMux()
	m.HandleFunc("GET /{$}", s.home)
	m.HandleFunc("GET /products/{slug}", s.product)
	m.HandleFunc("GET /products/{slug}/reviews", s.reviews)
	m.HandleFunc("GET /search", s.search)
	m.HandleFunc("GET /api/v1/items/{id}", s.item)
	m.HandleFunc("GET /static/{file}", s.static)
	m.HandleFunc("GET /img/{file}", s.image)
	m.HandleFunc("GET /account", s.account)
	m.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "public, max-age=60")
		http.Error(w, "not found", http.StatusNotFound)
	})
	s.mux = m
	return s
}

func (s *Shop) ServeHTTP(w http.ResponseWriter, r *http.Request) { s.mux.ServeHTTP(w, r) }

func randHex(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func lang(r *http.Request) string {
	l := strings.ToLower(strings.TrimSpace(r.Header.Get("Accept-Language")))
	switch {
	case strings.HasPrefix(l, "de"):
		return "de"
	case strings.HasPrefix(l, "fr"):
		return "fr"
	}
	return "en"
}

var addToCart = map[string]string{"en": "Add to cart", "de": "In den Warenkorb", "fr": "Ajouter au panier"}

func isMobile(ua string) bool {
	ua = strings.ToLower(ua)
	return strings.Contains(ua, "mobile") || strings.Contains(ua, "iphone") || strings.Contains(ua, "android")
}

// the html shell every page shares. nonce, csrf token, render time and the
// served-by comment change on every request.
func (s *Shop) page(w http.ResponseWriter, r *http.Request, title, canonical, body string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, `<!doctype html>
<html><head>
<meta charset="utf-8">
<title>%s | example shop</title>
<link rel="canonical" href="%s">
<meta name="csrf-token" content="%s">
<script nonce="%s">window.__boot = {release: "2026.10"};</script>
</head>
<body>
%s
<form action="/newsletter" method="post"><input type="hidden" name="authenticity_token" value="%s"><input name="email"></form>
<!-- served by app-%d in %dms -->
<footer>rendered %s</footer>
</body></html>
`, title, canonical, randHex(16), randHex(8), body, randHex(16), s.counter.Load()%7, 3+s.counter.Load()%40, s.now().UTC().Format(time.RFC3339))
}

// x-forwarded-host leaks into the canonical link. that's the classic
// unkeyed-input bug keyfold should flag.
func canonical(r *http.Request, path string) string {
	host := r.Host
	if xf := r.Header.Get("X-Forwarded-Host"); xf != "" {
		host = xf
	}
	return "https://" + host + path
}

func (s *Shop) home(w http.ResponseWriter, r *http.Request) {
	n := s.counter.Add(1)
	// "deal of the hour" flips on every request, so two identical requests
	// never return the same page. the prober has to learn that.
	deal := []string{"socks", "hats"}[n%2]
	layout := "desktop"
	if isMobile(r.UserAgent()) {
		layout = "mobile"
	}
	w.Header().Set("Cache-Control", "public, max-age=60")
	w.Header().Set("Vary", "User-Agent")
	s.page(w, r, "home", canonical(r, "/"), fmt.Sprintf(`<main class="%s"><h1>welcome</h1><aside>deal of the hour: %s</aside></main>`, layout, deal))
}

var prices = map[string]struct {
	sym  string
	rate float64
}{"USD": {"$", 1}, "EUR": {"€", 0.92}, "GBP": {"£", 0.79}}

func (s *Shop) product(w http.ResponseWriter, r *http.Request) {
	s.counter.Add(1)
	slug := r.PathValue("slug")
	i, ok := productIndex(slug)
	if !ok {
		w.Header().Set("Cache-Control", "public, max-age=60")
		http.Error(w, "no such product", http.StatusNotFound)
		return
	}
	q := r.URL.Query()
	color, size := q.Get("color"), q.Get("size")
	l := lang(r)
	// the currency cookie changes prices but the origin never says
	// "vary: cookie". any cache keyed on the url alone mixes currencies.
	cur := "USD"
	if c, err := r.Cookie("currency"); err == nil {
		if _, ok := prices[c.Value]; ok {
			cur = c.Value
		}
	}
	base := 10 + float64(h32(slug)%9000)/100
	if size == "xl" {
		base += 5
	}
	p := prices[cur]
	variant := "default"
	if color != "" || size != "" {
		variant = strings.TrimSpace(color + " " + size)
	}
	w.Header().Set("Cache-Control", "public, max-age=300")
	w.Header().Set("Vary", "Accept-Language")
	w.Header().Set("Content-Language", l)
	s.page(w, r, slug, canonical(r, "/products/"+slug), fmt.Sprintf(
		`<h1>%s</h1><p class="sku">sku %06d</p><p class="variant">%s</p><p class="price">%s%.2f</p><button>%s</button>`,
		strings.ReplaceAll(slug, "-", " "), i, variant, p.sym, base*p.rate, addToCart[l]))
}

func (s *Shop) reviews(w http.ResponseWriter, r *http.Request) {
	s.counter.Add(1)
	slug := r.PathValue("slug")
	if _, ok := productIndex(slug); !ok {
		w.Header().Set("Cache-Control", "public, max-age=60")
		http.Error(w, "no such product", http.StatusNotFound)
		return
	}
	q := r.URL.Query()
	page, _ := strconv.Atoi(q.Get("page"))
	if page < 1 {
		page = 1
	}
	order := q.Get("sort")
	if order != "newest" {
		order = "helpful"
	}
	var b strings.Builder
	for k := 0; k < 5; k++ {
		id := h32(slug, order, strconv.Itoa(page), strconv.Itoa(k)) % 100000
		fmt.Fprintf(&b, "<li>review %d: %d stars</li>", id, 1+id%5)
	}
	w.Header().Set("Cache-Control", "public, max-age=120")
	s.page(w, r, slug+" reviews", canonical(r, "/products/"+slug+"/reviews"), fmt.Sprintf(`<h1>reviews, page %d, %s first</h1><ul>%s</ul>`, page, order, b.String()))
}

func (s *Shop) search(w http.ResponseWriter, r *http.Request) {
	s.counter.Add(1)
	q := r.URL.Query()
	term := strings.TrimSpace(q.Get("q"))
	page, _ := strconv.Atoi(q.Get("page"))
	if page < 1 {
		page = 1
	}
	order := q.Get("sort")
	if order == "" {
		order = "relevance"
	}
	var b strings.Builder
	if term != "" {
		hits := make([]int, 0, 10)
		for k := 0; k < 10; k++ {
			hits = append(hits, int(h32(term, strconv.Itoa(page), strconv.Itoa(k))%NumProducts))
		}
		if order == "price" {
			sort.Ints(hits)
		}
		for _, id := range hits {
			fmt.Fprintf(&b, `<li><a href="/products/%s">%s</a></li>`, ProductSlug(id), ProductSlug(id))
		}
	}
	debug := ""
	if q.Get("debug") == "1" {
		debug = fmt.Sprintf("<pre>debug: index shard %d</pre>", h32(term)%16)
	}
	w.Header().Set("Cache-Control", "public, max-age=30")
	s.page(w, r, "search", canonical(r, "/search"), fmt.Sprintf(`<h1>results for %q, page %d by %s</h1><ol>%s</ol>%s`, term, page, order, b.String(), debug))
}

func (s *Shop) item(w http.ResponseWriter, r *http.Request) {
	n := s.counter.Add(1)
	id, err := strconv.Atoi(r.PathValue("id"))
	if err != nil || id < 1 || id > 5000 {
		w.Header().Set("Cache-Control", "public, max-age=60")
		http.Error(w, `{"error":"not found"}`, http.StatusNotFound)
		return
	}
	full := map[string]any{
		"id":     id,
		"name":   ProductSlug(id % NumProducts),
		"price":  10 + float64(h32(strconv.Itoa(id))%9000)/100,
		"stock":  h32("stock", strconv.Itoa(id)) % 40,
		"rating": float64(h32("rating", strconv.Itoa(id))%50) / 10,
	}
	out := map[string]any{"item": full}
	if f := r.URL.Query().Get("fields"); f != "" {
		sub := map[string]any{}
		for _, k := range strings.Split(f, ",") {
			if v, ok := full[k]; ok {
				sub[k] = v
			}
		}
		out["item"] = sub
	}
	out["request_id"] = randHex(8)
	out["server_time"] = s.now().Unix()
	// load balancer member, rotates per request. not a key the normaliser
	// knows about, so this is learned from baselines.
	out["served_by"] = fmt.Sprintf("api-%d", n%3)

	w.Header().Set("Cache-Control", "public, max-age=60")
	w.Header().Set("Vary", "Origin")
	if o := r.Header.Get("Origin"); strings.HasSuffix(o, ".example.com") || o == "https://example.com" {
		w.Header().Set("Access-Control-Allow-Origin", o)
	}
	body, _ := json.Marshal(out)
	if cb := r.URL.Query().Get("callback"); cb != "" {
		w.Header().Set("Content-Type", "application/javascript")
		fmt.Fprintf(w, "%s(%s);", cb, body)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(body)
}

func (s *Shop) static(w http.ResponseWriter, r *http.Request) {
	s.counter.Add(1)
	file := r.PathValue("file")
	parts := strings.Split(file, ".")
	if len(parts) != 3 || (parts[2] != "js" && parts[2] != "css") || (parts[1] != Builds[0] && parts[1] != Builds[1]) {
		w.Header().Set("Cache-Control", "public, max-age=60")
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	// ?v= is ignored: the build hash is already in the file name
	w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	if parts[2] == "js" {
		w.Header().Set("Content-Type", "text/javascript")
		fmt.Fprintf(w, "/* %s build %s */\n(function(){var n=%d;console.log(n)})();\n", parts[0], parts[1], h32(file))
		return
	}
	w.Header().Set("Content-Type", "text/css")
	fmt.Fprintf(w, "/* %s build %s */\nbody{margin:%dpx}\n", parts[0], parts[1], h32(file)%20)
}

func (s *Shop) image(w http.ResponseWriter, r *http.Request) {
	s.counter.Add(1)
	file := r.PathValue("file")
	name, ok := strings.CutSuffix(file, ".jpg")
	if !ok {
		w.Header().Set("Cache-Control", "public, max-age=60")
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	q := r.URL.Query()
	width := q.Get("w")
	if width == "" {
		width = "1280"
	}
	quality := q.Get("q")
	if quality == "" {
		quality = "80"
	}
	ct := "image/jpeg"
	if strings.Contains(r.Header.Get("Accept"), "image/avif") {
		ct = "image/avif"
	}
	w.Header().Set("Cache-Control", "public, max-age=86400")
	w.Header().Set("Vary", "Accept")
	w.Header().Set("Content-Type", ct)
	// not a real image, but bytes that depend on exactly what a resizer
	// would care about
	fmt.Fprintf(w, "IMG %s %s w=%s q=%s %08x", ct, name, width, quality, h32(name, width, quality, ct))
}

func (s *Shop) account(w http.ResponseWriter, r *http.Request) {
	s.counter.Add(1)
	w.Header().Set("Cache-Control", "private, no-store")
	http.SetCookie(w, &http.Cookie{Name: "sessionid", Value: randHex(12), Path: "/", HttpOnly: true})
	s.page(w, r, "account", canonical(r, "/account"), "<h1>your account</h1>")
}
