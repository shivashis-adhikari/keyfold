package fakeshop

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/shivashis-adhikari/keyfold/internal/logs"
	"github.com/shivashis-adhikari/keyfold/internal/routes"
)

func TestTrafficParsesInEveryFormat(t *testing.T) {
	for _, format := range []string{"nginx", "caddy", "cloudflare"} {
		var buf bytes.Buffer
		if err := WriteTraffic(&buf, TrafficOptions{Requests: 3000, Format: format, Seed: 7}); err != nil {
			t.Fatal(err)
		}
		p := filepath.Join(t.TempDir(), "access.log")
		os.WriteFile(p, buf.Bytes(), 0o644)
		s := logs.Open([]string{p}, logs.Options{DefaultHost: Host})
		n := 0
		var last *logs.Record
		for s.Scan() {
			n++
			r := *s.Record()
			last = &r
		}
		if s.Err() != nil || n != 3000 || s.Skipped != 0 {
			t.Errorf("%s: parsed %d, skipped %d, err %v, errors %v", format, n, s.Skipped, s.Err(), s.Errors)
		}
		if last == nil || last.Host != Host || last.Time.IsZero() {
			t.Errorf("%s: bad record %+v", format, last)
		}
	}
}

func TestTrafficDeterministic(t *testing.T) {
	var a, b bytes.Buffer
	WriteTraffic(&a, TrafficOptions{Requests: 500, Seed: 3})
	WriteTraffic(&b, TrafficOptions{Requests: 500, Seed: 3})
	if a.String() != b.String() {
		t.Error("same seed produced different logs")
	}
}

func get(t *testing.T, srv *httptest.Server, uri string, hdr ...string) (int, http.Header, string) {
	t.Helper()
	req, _ := http.NewRequest("GET", srv.URL+uri, nil)
	for i := 0; i+1 < len(hdr); i += 2 {
		req.Header.Set(hdr[i], hdr[i+1])
	}
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, resp.Header, string(body)
}

func TestShopBehaviour(t *testing.T) {
	srv := httptest.NewServer(New())
	defer srv.Close()
	slug := ProductSlug(17)

	code, h, body := get(t, srv, "/products/"+slug+"?color=red&utm_source=x")
	if code != 200 || !strings.Contains(body, "red") || h.Get("Vary") != "Accept-Language" {
		t.Fatalf("product page: %d %v", code, h)
	}
	_, _, de := get(t, srv, "/products/"+slug, "Accept-Language", "de-DE")
	if !strings.Contains(de, "Warenkorb") {
		t.Error("german page not served")
	}
	_, _, eur := get(t, srv, "/products/"+slug, "Cookie", "currency=EUR")
	if !strings.Contains(eur, "€") {
		t.Error("currency cookie ignored")
	}
	_, _, poisoned := get(t, srv, "/products/"+slug, "X-Forwarded-Host", "evil.invalid")
	if !strings.Contains(poisoned, "evil.invalid") {
		t.Error("x-forwarded-host should leak into the canonical link")
	}
	if code, _, _ := get(t, srv, "/products/nope-nope-99999"); code != 404 {
		t.Errorf("unknown product = %d", code)
	}
	_, h, _ = get(t, srv, "/account")
	if !strings.Contains(h.Get("Cache-Control"), "no-store") || h.Get("Set-Cookie") == "" {
		t.Errorf("account headers: %v", h)
	}
	_, h, _ = get(t, srv, "/img/"+imageNames[3]+".jpg?w=320", "Accept", "image/avif,*/*")
	if h.Get("Content-Type") != "image/avif" {
		t.Errorf("avif negotiation: %v", h)
	}
	_, h, _ = get(t, srv, "/api/v1/items/12", "Origin", "https://app.example.com")
	if h.Get("Access-Control-Allow-Origin") != "https://app.example.com" {
		t.Errorf("cors: %v", h)
	}
	if code, _, _ := get(t, srv, AssetPath("app", Builds[1], "js")+"?v=abc"); code != 200 {
		t.Errorf("asset = %d", code)
	}
}

func TestInferredRoutes(t *testing.T) {
	var buf bytes.Buffer
	WriteTraffic(&buf, TrafficOptions{Requests: 60000, Format: "cloudflare"})
	p := filepath.Join(t.TempDir(), "cf.json")
	os.WriteFile(p, buf.Bytes(), 0o644)
	s := logs.Open([]string{p}, logs.Options{})
	b := routes.NewBuilder(routes.Options{})
	for s.Scan() {
		b.Add(s.Record())
	}
	inv := b.Finish()
	got := map[string]*routes.Route{}
	for _, r := range inv.Routes {
		got[r.Pattern] = r
		t.Logf("%-32s %7d req  %6d urls  %5d paths  frag %.1f", r.Pattern, r.Requests, r.UniqueURLs, r.UniquePaths, r.Fragmentation())
	}
	for _, want := range []string{"/", "/products/{slug}", "/products/{slug}/reviews", "/search", "/api/v1/items/{int}",
		"/static/{asset}.js", "/static/{asset}.css", "/img/{name}.jpg", "/account"} {
		if got[want] == nil {
			t.Errorf("missing route %s", want)
		}
	}
	if r := got["/products/{slug}"]; r != nil && r.Fragmentation() < 2 {
		t.Errorf("product pages should be fragmented by tracking params, got %.2f", r.Fragmentation())
	}
}
