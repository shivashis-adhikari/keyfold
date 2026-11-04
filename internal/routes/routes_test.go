package routes

import (
	"fmt"
	"math"
	"regexp"
	"testing"
	"time"

	"github.com/shivashis-adhikari/keyfold/internal/logs"
)

func TestClassify(t *testing.T) {
	cases := map[string]string{
		"":                                     "",
		"products":                             "products",
		"12345":                                "{int}",
		"5f0c2b8e-1a2b-4c3d-9e8f-0123456789ab": "{uuid}",
		"2024-11-04":                           "{date}",
		"3f9c2a1b7d4e":                         "{hex}",
		"deadbeefcafe":                         "deadbeefcafe", // all letters, reads like a word
		"app.3f9c2a1b.js":                      "{asset}.js",
		"index-BkU7x2Pq.css":                   "{asset}.css",
		"logo.png":                             "logo.png",
		"42.jpg":                               "{int}.jpg",
		"blue-widget-3000":                     "blue-widget-3000",
		"the-best-running-shoes-of-2024":       "the-best-running-shoes-of-2024",
		"aZ3kP9qW2xL7mN4bV8cR":                 "{token}",
	}
	for in, want := range cases {
		if got := classify(in); got != want {
			t.Errorf("classify(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestSplitQuery(t *testing.T) {
	got := SplitQuery("b=2&a=1&&utm_source=news%20letter&flag&q=a+b")
	want := []Pair{
		{"b", "2", "b=2"},
		{"a", "1", "a=1"},
		{"utm_source", "news letter", "utm_source=news%20letter"},
		{"flag", "", "flag"},
		{"q", "a b", "q=a+b"},
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("got %v\nwant %v", got, want)
	}
}

func rec(host, uri string) *logs.Record {
	r := &logs.Record{Host: host, Method: "GET", Status: 200, Bytes: 1000, Time: time.Unix(1730721600, 0)}
	path, q, _ := cutQ(uri)
	r.Path, r.RawQuery = path, q
	return r
}

func cutQ(uri string) (string, string, bool) {
	for i := 0; i < len(uri); i++ {
		if uri[i] == '?' {
			return uri[:i], uri[i+1:], true
		}
	}
	return uri, "", false
}

func patterns(inv *Inventory) map[string]int64 {
	out := map[string]int64{}
	for _, r := range inv.Routes {
		out[r.Pattern] = r.Requests
	}
	return out
}

func TestCollapseSlugs(t *testing.T) {
	b := NewBuilder(Options{CollapseAt: 5})
	for i := 0; i < 40; i++ {
		b.Add(rec("shop", fmt.Sprintf("/products/widget-%c%c?color=red", 'a'+i%26, 'a'+i/26)))
		if i%4 == 0 {
			b.Add(rec("shop", fmt.Sprintf("/products/widget-%c%c/reviews?page=2", 'a'+i%26, 'a'+i/26)))
		}
	}
	// a handful of static pages at the root, plus a busy section
	for _, p := range []string{"/about", "/contact", "/pricing"} {
		b.Add(rec("shop", p))
	}
	for i := 0; i < 30; i++ {
		b.Add(rec("shop", fmt.Sprintf("/search?q=term%d", i)))
	}
	b.Add(rec("shop", "/products/new"))
	inv := b.Finish()
	got := patterns(inv)

	if got["/products/{slug}"] != 41 {
		// 40 widgets plus /products/new, which is just another slug once
		// folded
		t.Errorf("/products/{slug} = %d, want 41 (all: %v)", got["/products/{slug}"], got)
	}
	if got["/products/{slug}/reviews"] != 10 {
		t.Errorf("/products/{slug}/reviews = %d (all: %v)", got["/products/{slug}/reviews"], got)
	}
	for _, p := range []string{"/about", "/contact", "/pricing", "/search"} {
		if got[p] == 0 {
			t.Errorf("expected literal route %s, got %v", p, got)
		}
	}
}

func TestCollapseKeepsBusySections(t *testing.T) {
	b := NewBuilder(Options{CollapseAt: 3})
	for i := 0; i < 10; i++ {
		b.Add(rec("h", fmt.Sprintf("/page-%d-x", i)))
	}
	for i := 0; i < 100; i++ {
		b.Add(rec("h", "/catalog"))
	}
	got := patterns(b.Finish())
	if got["/catalog"] != 100 || got["/{slug}"] != 10 {
		t.Errorf("got %v", got)
	}
}

func TestCollapseByExtension(t *testing.T) {
	b := NewBuilder(Options{CollapseAt: 3})
	for i := 0; i < 6; i++ {
		b.Add(rec("h", fmt.Sprintf("/img/photo-%c.png", 'a'+i)))
		b.Add(rec("h", fmt.Sprintf("/img/icon-%c.svg", 'a'+i)))
	}
	got := patterns(b.Finish())
	if got["/img/{name}.png"] != 6 || got["/img/{name}.svg"] != 6 {
		t.Errorf("got %v", got)
	}
}

func TestInventoryStats(t *testing.T) {
	b := NewBuilder(Options{})
	for i := 0; i < 1000; i++ {
		r := rec("shop", fmt.Sprintf("/p/1?utm_source=s%d&color=%s", i%49, []string{"red", "blue"}[i%2]))
		r.Cookies = map[string]string{"currency": "EUR", "sessionid": fmt.Sprintf("secret%d", i)}
		b.Add(r)
	}
	b.Add(rec("shop", "/p/1?rare=1"))
	inv := b.Finish()
	if len(inv.Routes) != 1 {
		t.Fatalf("want one route, got %d", len(inv.Routes))
	}
	r := inv.Routes[0]
	if r.Pattern != "/p/{int}" || r.Requests != 1001 || r.UniquePaths != 1 {
		t.Errorf("route = %+v", r)
	}
	if r.UniqueURLs != 99 { // 49 sources x 2 colours, plus the rare one
		t.Errorf("unique urls = %d", r.UniqueURLs)
	}
	if p := r.Param("utm_source"); p == nil || p.Distinct != 49 || p.Requests != 1000 {
		t.Errorf("utm_source stats = %+v", p)
	}
	if p := r.Param("color"); p == nil || len(p.Top) != 2 {
		t.Errorf("color stats = %+v", p)
	}
	// the rare param must show up in at least one sample
	found := false
	for _, s := range r.Samples {
		if s.URI == "/p/1?rare=1" {
			found = true
		}
		if _, ok := s.Cookies["sessionid"]; ok {
			t.Errorf("sensitive cookie value leaked into a sample")
		}
	}
	if !found {
		t.Errorf("rare param not covered by samples: %v", r.Samples)
	}
	if c := r.Cookie("sessionid"); c == nil || c.Top[0].V != "" {
		t.Errorf("sessionid values should be blanked, got %+v", c)
	}
}

func TestMatcher(t *testing.T) {
	hosts := []string{"shop", "shop", "shop", "shop", "", "shop"}
	pats := []string{"/products/{slug}", "/products/new", "/products/{int}", "/static/{asset}.js", "/health", "/img/{name}.png"}
	m := NewMatcher(hosts, pats)
	cases := []struct {
		host, path string
		want       int
	}{
		{"shop", "/products/blue", 0},
		{"shop", "/products/new", 1},
		{"shop", "/products/123", 2},
		{"shop", "/static/app.3f9c2a1b.js", 3},
		{"shop", "/static/app.js", -1},
		{"other", "/health", 4},
		{"shop", "/health", 4},
		{"shop", "/img/a.png", 5},
		{"shop", "/img/a.jpg", -1},
		{"shop", "/products/blue/reviews", -1},
		{"shop", "/products/", -1},
	}
	for _, c := range cases {
		if got := m.Match(c.host, c.path); got != c.want {
			t.Errorf("Match(%s, %s) = %d, want %d", c.host, c.path, got, c.want)
		}
	}
}

func TestRegexAndWildcard(t *testing.T) {
	cases := []struct {
		pat, re, wc string
		yes, no     []string
	}{
		{"/products/{slug}", `^/products/[^/]+$`, "/products/*", []string{"/products/a-b"}, []string{"/products/a/b", "/products/"}},
		{"/static/{asset}.js", `^/static/[^/]+?[.]js$`, "/static/*.js", []string{"/static/app.123abc.js"}, []string{"/static/app.css"}},
		{"/api/v1/items/{int}", `^/api/v1/items/[0-9]+$`, "/api/v1/items/*", []string{"/api/v1/items/9"}, []string{"/api/v1/items/x"}},
		{"/", `^/$`, "/", []string{"/"}, []string{"/a"}},
	}
	for _, c := range cases {
		if got := Regex(c.pat); got != c.re {
			t.Errorf("Regex(%s) = %s, want %s", c.pat, got, c.re)
		}
		if got := Wildcard(c.pat); got != c.wc {
			t.Errorf("Wildcard(%s) = %s, want %s", c.pat, got, c.wc)
		}
		re := regexp.MustCompile(Regex(c.pat))
		for _, p := range c.yes {
			if !re.MatchString(p) {
				t.Errorf("%s should match %s", Regex(c.pat), p)
			}
		}
		for _, p := range c.no {
			if re.MatchString(p) {
				t.Errorf("%s should not match %s", Regex(c.pat), p)
			}
		}
	}
}

func TestDistinctAccuracy(t *testing.T) {
	for _, n := range []int{10, 2000, 5000, 100000, 1000000} {
		var d distinct
		for i := 0; i < n; i++ {
			d.add(hashString(fmt.Sprintf("/p/%d?x=%d", i, i*7)))
		}
		got := float64(d.count())
		if err := math.Abs(got-float64(n)) / float64(n); err > 0.05 {
			t.Errorf("n=%d estimate=%v error=%.3f", n, got, err)
		}
	}
}

func TestDistinctMerge(t *testing.T) {
	var a, b distinct
	for i := 0; i < 3000; i++ {
		a.add(hashString(fmt.Sprint(i)))
	}
	for i := 1500; i < 4500; i++ {
		b.add(hashString(fmt.Sprint(i)))
	}
	a.merge(&b)
	if got := a.count(); math.Abs(float64(got)-4500)/4500 > 0.05 {
		t.Errorf("merged count = %d, want about 4500", got)
	}
}

func TestNameHints(t *testing.T) {
	for _, n := range []string{"utm_source", "UTM_Campaign", "fbclid", "gclid", "utm_whatever"} {
		if !IsTracker(n) {
			t.Errorf("%s should be a tracker", n)
		}
	}
	for _, n := range []string{"page", "q", "color", "v"} {
		if IsTracker(n) {
			t.Errorf("%s is not a tracker", n)
		}
	}
	for _, n := range []string{"sessionid", "PHPSESSID", "auth_token", "remember_me", "_ga", "__cf_bm"} {
		if !IsSensitive(n) {
			t.Errorf("%s should be sensitive", n)
		}
	}
	for _, n := range []string{"currency", "lang", "theme", "consent"} {
		if IsSensitive(n) {
			t.Errorf("%s should not be sensitive", n)
		}
	}
}
