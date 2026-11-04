package synth

import (
	"bytes"
	"context"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/shivashis-adhikari/keyfold/internal/fakeshop"
	"github.com/shivashis-adhikari/keyfold/internal/logs"
	"github.com/shivashis-adhikari/keyfold/internal/plan"
	"github.com/shivashis-adhikari/keyfold/internal/probe"
	"github.com/shivashis-adhikari/keyfold/internal/routes"
)

func res(part, name, op, verdict string) probe.Result {
	return probe.Result{Part: part, Name: name, Op: op, Verdict: verdict, Detail: "d"}
}

func report(results ...probe.Result) *probe.Report {
	inv := &routes.Inventory{HasHeaders: true, Routes: []*routes.Route{{
		Host: "h", Pattern: "/p/{int}", Requests: 1000,
		Params: []*routes.Param{
			{Name: "color", Requests: 400, Distinct: 5},
			{Name: "utm_source", Requests: 300, Distinct: 7, Top: []routes.Value{{V: "news", N: 100}, {V: "fb", N: 50}}},
			{Name: "v", Requests: 200, Distinct: 2},
			{Name: "rare", Requests: 5, Distinct: 5},
			{Name: "page", Requests: 100, Distinct: 9},
			{Name: "fbclid", Requests: 80, Distinct: 80},
		},
	}}}
	return &probe.Report{Inv: inv, Routes: []*probe.RouteResult{{
		Host: "h", Pattern: "/p/{int}",
		Cache:   probe.CacheInfo{Cacheable: true, TTL: 300, Vary: []string{"accept-language"}},
		Samples: []*probe.SampleResult{{URI: "/p/1?color=red", Results: results}},
	}}}
}

func TestQueryDecisions(t *testing.T) {
	rep := report(
		res("query", "color", "drop", probe.Changes),
		res("query", "color", "mutate", probe.Changes),
		res("query", "utm_source", "drop", probe.Noise),
		res("query", "utm_source", "mutate", probe.Noise),
		res("query", "v", "drop", probe.Noise),
		res("query", "v", "mutate", probe.Noise),
		res("query", "page", "drop", probe.Noise),
		res("query", "page", "mutate", probe.Unknown),
		res("order", "query", "reorder", probe.Noise),
	)
	p := Synthesize(rep, Options{})
	r := p.Routes[0]
	if !slices.Equal(r.Query.Keep, []string{"color", "v"}) {
		t.Errorf("keep = %v", r.Query.Keep)
	}
	if !slices.Equal(r.Query.Drop, []string{"utm_source"}) {
		t.Errorf("drop = %v", r.Query.Drop)
	}
	// page was inconclusive, rare and fbclid never probed: all stay in
	if !slices.Equal(r.Query.Unverified, []string{"fbclid", "page", "rare"}) {
		t.Errorf("unverified = %v", r.Query.Unverified)
	}
	if !r.Query.Sort || !r.Cacheable || r.TTL != 300 {
		t.Errorf("route = %+v", r)
	}
	if got := r.Values["utm_source"]; !slices.Equal(got, []string{"news", "fb"}) {
		t.Errorf("values for canary = %v", got)
	}
	kinds := map[string]bool{}
	for _, f := range r.Flags {
		kinds[f.Kind+":"+f.Name] = true
	}
	for _, k := range []string{"version-param:v", "unverified:page", "unverified:fbclid"} {
		if !kinds[k] {
			t.Errorf("missing flag %s in %v", k, r.Flags)
		}
	}
	if kinds["unverified:rare"] {
		t.Error("a param on 0.5% of requests shouldn't get a warning")
	}

	// trusting the tracker list drops fbclid without evidence
	p = Synthesize(rep, Options{TrustTrackers: true})
	if !slices.Contains(p.Routes[0].Query.Drop, "fbclid") {
		t.Errorf("fbclid should be dropped by name, drop=%v", p.Routes[0].Query.Drop)
	}
}

func TestMinEvidence(t *testing.T) {
	rep := report(res("query", "utm_source", "drop", probe.Noise))
	if p := Synthesize(rep, Options{}); slices.Contains(p.Routes[0].Query.Drop, "utm_source") {
		t.Error("one noise verdict is not enough by default")
	}
	if p := Synthesize(rep, Options{MinEvidence: 1}); !slices.Contains(p.Routes[0].Query.Drop, "utm_source") {
		t.Error("min evidence 1 should drop it")
	}
}

func TestTrackerThatMatters(t *testing.T) {
	rep := report(res("query", "utm_source", "mutate", probe.Changes))
	p := Synthesize(rep, Options{})
	found := false
	for _, f := range p.Routes[0].Flags {
		if f.Kind == "unsafe-drop" && f.Name == "utm_source" && f.Level == plan.High {
			found = true
		}
	}
	if !found {
		t.Errorf("expected an unsafe-drop flag, got %v", p.Routes[0].Flags)
	}
}

func TestHeadersAndCookies(t *testing.T) {
	rep := report(
		res("header", "accept-language", "same-class", probe.Noise),
		res("header", "accept-language", "other-class", probe.Changes),
		res("header", "user-agent", "same-class", probe.Noise),
		res("header", "user-agent", "other-class", probe.Changes),
		res("header", "x-forwarded-host", "add", probe.Changes),
		res("cookie", "currency", "drop", probe.Changes),
		res("cookie", "currency", "mutate", probe.Changes),
		res("cookie", "beta", "drop", probe.Changes),
		res("cookie", "beta", "mutate", probe.Noise),
		res("cookie", "theme", "add", probe.Changes),
		res("order", "query", "reorder", probe.Changes),
	)
	r := Synthesize(rep, Options{}).Routes[0]
	if !r.Header.Lang || !r.Header.Device || len(r.Header.Include) != 0 {
		t.Errorf("header key = %+v", r.Header)
	}
	if !slices.Equal(r.Cookie.Include, []string{"currency", "theme"}) || !slices.Equal(r.Cookie.Presence, []string{"beta"}) {
		t.Errorf("cookie key = %+v", r.Cookie)
	}
	if r.Query.Sort {
		t.Error("order changed the response, sort must be off")
	}
	var high []string
	for _, f := range r.Flags {
		if f.Level == plan.High {
			high = append(high, f.Kind+":"+f.Name)
		}
	}
	for _, want := range []string{"unkeyed-input:x-forwarded-host", "order-matters:", "vary-cookie:currency", "vary-header:accept-language"} {
		if !slices.Contains(high, want) {
			t.Errorf("missing high flag %s, have %v", want, high)
		}
	}
	if slices.ContainsFunc(r.Flags, func(f plan.Flag) bool { return f.Kind == "uncovered" }) {
		t.Errorf("x-forwarded-host is flagged as unkeyed input, not as an uncovered gap: %v", r.Flags)
	}
}

func TestRawHeaderVariance(t *testing.T) {
	rep := report(
		res("header", "user-agent", "same-class", probe.Changes),
		res("header", "user-agent", "other-class", probe.Changes),
	)
	r := Synthesize(rep, Options{}).Routes[0]
	if r.Header.Device || !slices.Contains(r.Header.Include, "user-agent") {
		t.Errorf("raw user-agent variance should key on the raw header: %+v", r.Header)
	}
}

// the whole loop against the fake shop: logs, probe, plan. this is the
// answer key for the shop's quirks.
func TestShopPlan(t *testing.T) {
	if testing.Short() {
		t.Skip("probes the fake shop")
	}
	var buf bytes.Buffer
	fakeshop.WriteTraffic(&buf, fakeshop.TrafficOptions{Requests: 30000, Format: "cloudflare"})
	path := filepath.Join(t.TempDir(), "cf.json")
	os.WriteFile(path, buf.Bytes(), 0o644)
	sc := logs.Open([]string{path}, logs.Options{})
	b := routes.NewBuilder(routes.Options{})
	for sc.Scan() {
		b.Add(sc.Record())
	}
	srv := httptest.NewServer(fakeshop.New())
	defer srv.Close()
	origin, _ := url.Parse(srv.URL)
	rep, err := probe.Run(context.Background(), b.Finish(), probe.Options{Origin: origin, HostHeader: fakeshop.Host, Rate: 5000, Concurrency: 8, Client: srv.Client()})
	if err != nil {
		t.Fatal(err)
	}
	p := Synthesize(rep, Options{})
	by := map[string]*plan.Route{}
	for _, r := range p.Routes {
		by[r.Pattern] = r
	}
	prod := by["/products/{slug}"]
	if prod == nil {
		t.Fatal("no product route")
	}
	for _, n := range []string{"utm_source", "utm_medium", "utm_campaign", "fbclid", "gclid"} {
		if !slices.Contains(prod.Query.Drop, n) {
			t.Errorf("products should drop %s, plan %+v", n, prod.Query)
		}
	}
	for _, n := range []string{"color", "size"} {
		if !slices.Contains(prod.Query.Keep, n) {
			t.Errorf("products must keep %s, plan %+v", n, prod.Query)
		}
	}
	if !prod.Header.Lang || !slices.Contains(prod.Cookie.Include, "currency") || !prod.Query.Sort {
		t.Errorf("products key: %+v %+v sort=%v", prod.Header, prod.Cookie, prod.Query.Sort)
	}
	if r := by["/static/{asset}.js"]; r == nil || !slices.Contains(r.Query.Keep, "v") {
		t.Errorf("static assets must keep ?v: %+v", r)
	}
	if r := by["/api/v1/items/{int}"]; r == nil || !slices.Contains(r.Query.Drop, "_") || !slices.Contains(r.Query.Keep, "fields") {
		t.Errorf("api: %+v", r)
	}
	if r := by["/"]; r == nil || !r.Header.Device {
		t.Errorf("home should key on device: %+v", r)
	}
	if r := by["/account"]; r != nil && r.Cacheable {
		t.Error("account must not be cacheable")
	}
	for _, r := range p.Routes {
		for _, f := range r.Flags {
			if f.Kind == "uncovered" {
				t.Errorf("%s: %s", r.Pattern, f.Detail)
			}
			if testing.Verbose() {
				t.Logf("%-28s %-5s %-15s %s", r.Pattern, f.Level, f.Kind, strings.TrimSpace(f.Detail))
			}
		}
	}
}
