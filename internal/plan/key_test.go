package plan

import (
	"testing"

	"github.com/shivashis-adhikari/keyfold/internal/logs"
)

func testPlan(mode string) *Plan {
	return &Plan{Version: 1, Mode: mode, Routes: []*Route{
		{
			Host: "shop", Pattern: "/products/{slug}", Cacheable: true,
			Query:  Query{Keep: []string{"color", "size"}, Drop: []string{"utm_source", "fbclid"}, Unverified: []string{"ref"}, Sort: true},
			Header: Header{Lang: true},
			Cookie: Cookie{Include: []string{"currency"}, Presence: []string{"beta"}},
		},
		{Host: "shop", Pattern: "/search", Cacheable: true, Query: Query{Keep: []string{"q"}}},
	}}
}

func key(k *Keyer, r *logs.Record) string {
	return string(k.Proposed(r, k.Route(r), nil))
}

func TestProposedSafe(t *testing.T) {
	k := NewKeyer(testPlan(Safe))
	base := logs.Record{Scheme: "https", Host: "shop", Path: "/products/blue-widget", Header: map[string]string{"accept-language": "de-DE,de;q=0.9"}}

	a, b := base, base
	a.RawQuery = "utm_source=news&size=m&color=red&fbclid=abc"
	b.RawQuery = "color=red&size=m&utm_source=fb"
	if key(k, &a) != key(k, &b) {
		t.Errorf("tracking params and order should not split the key:\n%s\n%s", key(k, &a), key(k, &b))
	}
	want := "https://shop/products/blue-widget?color=red&size=m|lang=de|c:currency=|p:beta"
	if got := key(k, &a); got != want {
		t.Errorf("key = %s\nwant %s", got, want)
	}

	// safe mode keeps a param nobody has seen before
	c := base
	c.RawQuery = "color=red&size=m&newthing=1"
	if key(k, &c) == key(k, &a) {
		t.Error("safe mode must keep unknown params")
	}
	d := base
	d.RawQuery = a.RawQuery
	d.Cookies = map[string]string{"currency": "EUR", "beta": "1"}
	if key(k, &d) == key(k, &a) {
		t.Error("cookies must split the key")
	}
	e := base
	e.RawQuery = a.RawQuery
	e.Header = map[string]string{"accept-language": "de-AT"}
	if key(k, &e) != key(k, &a) {
		t.Error("same primary language should share a key")
	}
}

func TestProposedTight(t *testing.T) {
	k := NewKeyer(testPlan(Tight))
	r := logs.Record{Scheme: "https", Host: "shop", Path: "/products/x", RawQuery: "newthing=1&color=red&ref=a"}
	if got := key(k, &r); got != "https://shop/products/x?color=red&ref=a|lang=|c:currency=|p:beta" {
		t.Errorf("tight key = %s", got)
	}
}

func TestOutsidePlanUsesCurrentKey(t *testing.T) {
	k := NewKeyer(testPlan(Safe))
	r := logs.Record{Scheme: "https", Host: "shop", Path: "/about", RawQuery: "utm_source=x&b=1&a=2"}
	if k.Route(&r) != -1 {
		t.Fatal("/about isn't in the plan")
	}
	if got, cur := key(k, &r), string(Current(&r, nil)); got != cur || cur != "https://shop/about?utm_source=x&b=1&a=2" {
		t.Errorf("got %s, current %s", got, cur)
	}
	// no sort on /search: order stays as sent
	s := logs.Record{Scheme: "https", Host: "shop", Path: "/search", RawQuery: "q=a&page=2"}
	if got := key(k, &s); got != "https://shop/search?q=a&page=2" {
		t.Errorf("got %s", got)
	}
}

func TestPlanRoundTrip(t *testing.T) {
	p := testPlan(Safe)
	path := t.TempDir() + "/plan.json"
	if err := p.Save(path); err != nil {
		t.Fatal(err)
	}
	q, err := Load(path)
	if err != nil || len(q.Routes) != 2 || q.Routes[0].Query.Keep[1] != "size" {
		t.Fatalf("round trip: %v %+v", err, q)
	}
	if !q.Routes[0].Changed() {
		t.Error("route 0 changes the key")
	}
}

func BenchmarkProposed(b *testing.B) {
	k := NewKeyer(testPlan(Safe))
	r := logs.Record{Scheme: "https", Host: "shop", Path: "/products/blue-widget-17", RawQuery: "utm_source=news&size=m&color=red&fbclid=IwAR2xyzzy&utm_campaign=bf_2025",
		Header: map[string]string{"accept-language": "en-US,en;q=0.9"}}
	var buf []byte
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		buf = k.Proposed(&r, k.Route(&r), buf[:0])
	}
}
