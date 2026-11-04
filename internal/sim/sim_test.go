package sim

import (
	"bytes"
	"math"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/shivashis-adhikari/keyfold/internal/fakeshop"
	"github.com/shivashis-adhikari/keyfold/internal/logs"
	"github.com/shivashis-adhikari/keyfold/internal/plan"
)

// what the synthesiser produces for the shop, written out by hand so this
// test doesn't depend on probing.
func shopPlan() *plan.Plan {
	trackers := []string{"fbclid", "gclid", "ref", "utm_campaign", "utm_content", "utm_medium", "utm_source"}
	return &plan.Plan{Version: 1, Mode: plan.Safe, Routes: []*plan.Route{
		{Host: fakeshop.Host, Pattern: "/products/{slug}", Cacheable: true, TTL: 300,
			Query: plan.Query{Keep: []string{"color", "size"}, Drop: trackers, Sort: true}, Header: plan.Header{Lang: true}, Cookie: plan.Cookie{Include: []string{"currency"}}},
		{Host: fakeshop.Host, Pattern: "/", Cacheable: true, TTL: 60, Query: plan.Query{Drop: trackers, Sort: true}, Header: plan.Header{Device: true}},
		{Host: fakeshop.Host, Pattern: "/api/v1/items/{int}", Cacheable: true, TTL: 60, Query: plan.Query{Keep: []string{"fields", "callback"}, Drop: []string{"_"}, Sort: true}},
		{Host: fakeshop.Host, Pattern: "/account", Cacheable: false},
	}}
}

func shopTrace(t *testing.T, n int) *Trace {
	t.Helper()
	var buf bytes.Buffer
	fakeshop.WriteTraffic(&buf, fakeshop.TrafficOptions{Requests: n, Format: "cloudflare", Span: 6 * time.Hour})
	p := filepath.Join(t.TempDir(), "cf.json")
	os.WriteFile(p, buf.Bytes(), 0o644)
	tr, err := Build(logs.Open([]string{p}, logs.Options{}), shopPlan(), BuildOptions{})
	if err != nil {
		t.Fatal(err)
	}
	return tr
}

func TestBuild(t *testing.T) {
	tr := shopTrace(t, 20000)
	if tr.Lines != 20000 || tr.Skipped != 0 {
		t.Fatalf("lines=%d skipped=%d", tr.Lines, tr.Skipped)
	}
	if tr.Uncacheable == 0 || tr.Uncacheable > 1000 {
		t.Errorf("account traffic should be filtered, uncacheable=%d", tr.Uncacheable)
	}
	if tr.PropKeys >= tr.CurKeys || tr.PropFootprint >= tr.CurFootprint {
		t.Errorf("planned key should collapse entries: %d -> %d keys", tr.CurKeys, tr.PropKeys)
	}
	if tr.ObservedTotal == 0 || !tr.HasHeaders || !tr.HasCookies {
		t.Errorf("trace metadata missing: %+v", tr.ObservedTotal)
	}
	for i := 1; i < tr.Len(); i++ {
		if tr.Time[i] < tr.Time[i-1] {
			t.Fatal("trace not sorted by time")
		}
	}
	if tr.TTL[0] != 300_000 || tr.TTL[len(tr.TTL)-1] != time.Hour.Milliseconds() {
		t.Errorf("ttls = %v", tr.TTL)
	}
}

func TestRun(t *testing.T) {
	tr := shopTrace(t, 30000)
	sizes, _ := ParseSizes("1%,10%,100%")
	res, err := Run(tr, Config{Policies: []string{"lru", "fifo", "sieve", "s3fifo", "tinylfu"}, Sizes: sizes})
	if err != nil {
		t.Fatal(err)
	}
	inf := res[len(res)-1]
	if inf.Policy != "inf" {
		t.Fatal("last result should be the infinite cache")
	}
	for _, r := range res {
		if r.Current.Requests != int64(tr.Len()) || r.Proposed.Requests != int64(tr.Len()) {
			t.Errorf("%s/%s replayed %d/%d of %d", r.Policy, r.Size, r.Current.Requests, r.Proposed.Requests, tr.Len())
		}
		if r.Proposed.Hits < r.Current.Hits {
			t.Errorf("%s/%s: planned key lost hits, %d < %d", r.Policy, r.Size, r.Proposed.Hits, r.Current.Hits)
		}
		if r.Proposed.Hits > inf.Proposed.Hits || r.Current.Hits > inf.Current.Hits {
			t.Errorf("%s/%s beats the infinite cache", r.Policy, r.Size)
		}
		t.Logf("%-8s %5s  hit %.3f -> %.3f   byte hit %.3f -> %.3f", r.Policy, r.Size,
			r.Current.HitRatio(), r.Proposed.HitRatio(), r.Current.ByteHitRatio(), r.Proposed.ByteHitRatio())
	}
	// lru has the stack property: more space never means fewer hits
	var last int64
	for _, r := range res {
		if r.Policy == "lru" {
			if r.Current.Hits < last {
				t.Errorf("lru lost hits going to %s", r.Size)
			}
			last = r.Current.Hits
		}
	}
}

func TestByRoute(t *testing.T) {
	tr := shopTrace(t, 20000)
	rs := ByRoute(tr, "lru", Size{Fraction: 0.1})
	var total int64
	for _, r := range rs {
		total += r.Current.Requests
		if r.Proposed.Requests != r.Current.Requests {
			t.Errorf("%s: request counts differ", r.Route)
		}
	}
	if total != int64(tr.Len()) {
		t.Errorf("per-route totals %d != %d", total, tr.Len())
	}
}

func TestParseSizes(t *testing.T) {
	got, err := ParseSizes("0.5%, 10%,512MB,4GiB,100k")
	if err != nil {
		t.Fatal(err)
	}
	if got[0].Fraction != 0.005 || got[2].Bytes != 512e6 || got[3].Bytes != 4<<30 || got[4].Bytes != 100<<10 {
		t.Errorf("parsed %+v", got)
	}
	for _, bad := range []string{"", "x%", "-1GB", "lots"} {
		if _, err := ParseSizes(bad); err == nil {
			t.Errorf("%q should fail", bad)
		}
	}
}

func TestCosts(t *testing.T) {
	c := Costs{EgressPerGB: 0.09, PerMillion: 0.5}
	s := Stats{Requests: 2_000_000, Hits: 1_000_000, Bytes: 20e9, HitBytes: 10e9}
	// one day of traffic: 10gb and 1m origin requests a day, times 30
	got := c.Monthly(s, 24*time.Hour)
	if want := 30 * (10*0.09 + 0.5); math.Abs(got-want) > 1e-9 {
		t.Errorf("monthly = %v, want %v", got, want)
	}
}

func TestHumanBytes(t *testing.T) {
	for n, want := range map[int64]string{512: "512 B", 2048: "2.0 KiB", 5 << 30: "5.0 GiB"} {
		if got := HumanBytes(n); got != want {
			t.Errorf("HumanBytes(%d) = %s", n, got)
		}
	}
}
