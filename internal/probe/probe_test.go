package probe

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"

	"github.com/shivashis-adhikari/keyfold/internal/fakeshop"
	"github.com/shivashis-adhikari/keyfold/internal/logs"
	"github.com/shivashis-adhikari/keyfold/internal/routes"
)

func shopInventory(t *testing.T, n int) *routes.Inventory {
	t.Helper()
	var buf bytes.Buffer
	if err := fakeshop.WriteTraffic(&buf, fakeshop.TrafficOptions{Requests: n, Format: "cloudflare"}); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "cf.json")
	os.WriteFile(p, buf.Bytes(), 0o644)
	s := logs.Open([]string{p}, logs.Options{})
	b := routes.NewBuilder(routes.Options{})
	for s.Scan() {
		b.Add(s.Record())
	}
	return b.Finish()
}

// verdict per part name across all samples of a route. "changes" wins over
// anything else, like the synthesiser treats it.
func verdicts(rr *RouteResult) map[string]string {
	out := map[string]string{}
	for _, s := range rr.Samples {
		for _, r := range s.Results {
			key := r.Part + ":" + r.Name
			if r.Op == "same-class" || r.Op == "other-class" {
				key += ":" + r.Op
			}
			switch {
			case out[key] == Changes:
			case r.Verdict == Changes:
				out[key] = Changes
			case out[key] == "" || r.Verdict == Unknown:
				out[key] = r.Verdict
			}
		}
	}
	return out
}

func TestProbeAgainstShop(t *testing.T) {
	if testing.Short() {
		t.Skip("probes a few thousand requests")
	}
	inv := shopInventory(t, 30000)
	srv := httptest.NewServer(fakeshop.New())
	defer srv.Close()
	origin, _ := url.Parse(srv.URL)

	rep, err := Run(context.Background(), inv, Options{
		Origin: origin, HostHeader: fakeshop.Host, Rate: 5000, Concurrency: 8, Samples: 3,
		Client: srv.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}
	byPattern := map[string]*RouteResult{}
	for _, rr := range rep.Routes {
		byPattern[rr.Pattern] = rr
	}

	check := func(pattern string, want map[string]string) {
		t.Helper()
		rr := byPattern[pattern]
		if rr == nil {
			t.Errorf("%s was not probed", pattern)
			return
		}
		got := verdicts(rr)
		for k, v := range want {
			if got[k] != v {
				t.Errorf("%s %s = %q, want %q", pattern, k, got[k], v)
			}
		}
		if t.Failed() {
			for _, s := range rr.Samples {
				t.Logf("  sample %s stable=%v volatile=%d", s.URI, s.Stable, s.Volatile)
				for _, r := range s.Results {
					t.Logf("    %-7s %-18s %-12s %-8s %s", r.Part, r.Name, r.Op, r.Verdict, r.Detail)
				}
			}
		}
	}

	check("/products/{slug}", map[string]string{
		"query:color":                        Changes,
		"query:size":                         Changes,
		"query:utm_source":                   Noise,
		"query:utm_campaign":                 Noise,
		"query:fbclid":                       Noise,
		"query:gclid":                        Noise,
		"order:query":                        Noise,
		"cookie:currency":                    Changes,
		"header:accept-language:same-class":  Noise,
		"header:accept-language:other-class": Changes,
		"header:user-agent:same-class":       Noise,
		"header:user-agent:other-class":      Noise,
		"header:x-forwarded-host":            Changes,
		"header:accept":                      Noise,
	})
	check("/", map[string]string{
		"query:utm_source":              Noise,
		"query:fbclid":                  Noise,
		"header:user-agent:same-class":  Noise,
		"header:user-agent:other-class": Changes,
	})
	check("/search", map[string]string{
		"query:q":          Changes,
		"query:page":       Changes,
		"query:sort":       Changes,
		"query:utm_source": Noise,
	})
	check("/api/v1/items/{int}", map[string]string{
		"query:_":       Noise,
		"query:fields":  Changes,
		"header:origin": Changes,
	})
	check("/static/{asset}.js", map[string]string{"query:v": Noise})
	check("/img/{name}.jpg", map[string]string{"query:w": Changes, "header:accept": Changes})

	if rr := byPattern["/account"]; rr != nil && rr.Cache.Cacheable {
		t.Errorf("/account should be uncacheable: %+v", rr.Cache)
	}
	if rr := byPattern["/products/{slug}"]; rr != nil {
		if !rr.Cache.Cacheable || rr.Cache.TTL != 300 {
			t.Errorf("product cache info: %+v", rr.Cache)
		}
	}
	// the deal flips per home page request. with several workers sharing
	// that counter one of them can end up phase locked and only ever see
	// one deal, so only ask that the instability was noticed somewhere.
	if rr := byPattern["/"]; rr != nil {
		unstable := 0
		for _, s := range rr.Samples {
			if !s.Stable {
				unstable++
			}
		}
		if unstable == 0 {
			t.Errorf("home page flips its deal on every request, no sample noticed")
		}
	}
	t.Logf("%d requests total", rep.Requests)
}

func TestCacheInfo(t *testing.T) {
	cases := []struct {
		status int
		h      http.Header
		ok     bool
		ttl    int64
	}{
		{200, http.Header{"Cache-Control": {"public, max-age=300"}}, true, 300},
		{200, http.Header{"Cache-Control": {"max-age=60, s-maxage=600"}}, true, 600},
		{200, http.Header{"Cache-Control": {"private, max-age=60"}}, false, 60},
		{200, http.Header{"Cache-Control": {"no-store"}}, false, 0},
		{200, http.Header{"Cache-Control": {"public, max-age=60"}, "Set-Cookie": {"a=b"}}, false, 60},
		{302, http.Header{}, false, 0},
		{404, http.Header{}, true, 0},
		{200, http.Header{"Cache-Control": {"max-age=0"}}, false, 0},
	}
	for i, c := range cases {
		ci := cacheInfo(c.status, c.h)
		if ci.Cacheable != c.ok || ci.TTL != c.ttl {
			t.Errorf("case %d: %+v", i, ci)
		}
	}
}

func TestAlternative(t *testing.T) {
	stats := &routes.Param{Top: []routes.Value{{V: "red", N: 10}, {V: "blue", N: 4}}}
	if got := alternative("red", stats); got != "blue" {
		t.Errorf("got %q", got)
	}
	for in, want := range map[string]string{"1": "2", "7": "8", "true": "false", "": "1", "abc": "abcx"} {
		if got := alternative(in, nil); got != want {
			t.Errorf("alternative(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestStripParam(t *testing.T) {
	if got := stripParam("/a?x=1&kfcb=99&y=2", "kfcb"); got != "/a?x=1&y=2" {
		t.Errorf("got %s", got)
	}
	if got := stripParam("/a?kfcb=99", "kfcb"); got != "/a" {
		t.Errorf("got %s", got)
	}
}
