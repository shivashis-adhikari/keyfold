package logs

import (
	"bytes"
	"compress/gzip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const (
	cfLineHit = `{"CacheCacheStatus":"hit","ClientRequestHost":"Shop.Example.com","ClientRequestMethod":"GET","ClientRequestURI":"/products/blue-widget?utm_source=newsletter&color=blue","ClientRequestScheme":"https","ClientRequestUserAgent":"Mozilla/5.0 (X11; Linux x86_64)","EdgeResponseBytes":48213,"EdgeResponseBodyBytes":47702,"EdgeResponseStatus":200,"EdgeStartTimestamp":1730721600123456789,"RayID":"8dd1f0c0d9a2b3c4","Cookies":{"currency":"EUR"}}`
	cfLineRFC = `{"CacheCacheStatus":"miss","ClientRequestHost":"shop.example.com","ClientRequestMethod":"GET","ClientRequestPath":"/static/app.js","EdgeResponseBytes":1200,"EdgeResponseStatus":200,"EdgeStartTimestamp":"2024-11-04T12:00:00Z"}`

	caddyLineTLS    = `{"level":"info","ts":1730721600.5241024,"logger":"http.log.access.log0","msg":"handled request","request":{"remote_ip":"203.0.113.9","remote_port":"41342","client_ip":"203.0.113.9","proto":"HTTP/2.0","method":"GET","host":"shop.example.com:443","uri":"/search?q=boots&page=2","headers":{"User-Agent":["curl/8.5.0"],"Accept":["*/*"],"Cookie":["REDACTED"]},"tls":{"resumed":false,"version":772,"cipher_suite":4865,"proto":"h2","server_name":"shop.example.com"}},"bytes_read":0,"user_id":"","duration":0.000929675,"size":10900,"status":200,"resp_headers":{"Server":["Caddy"],"Cache-Status":["Souin; hit; ttl=3542; key=GET-https-shop.example.com-/search?q=boots&page=2"],"Content-Type":["text/html; charset=utf-8"]}}`
	caddyLineCookie = `{"level":"info","ts":"2024-11-04T12:00:01.250Z","logger":"http.log.access","msg":"handled request","request":{"method":"GET","host":"shop.example.com","uri":"/","headers":{"Cookie":["currency=EUR; theme=\"dark\""],"Accept-Language":["de-DE,de;q=0.9"]}},"size":512,"status":200,"resp_headers":{"Cache-Status":["Souin; fwd=uri-miss; stored"]}}`
	caddyRuntime    = `{"level":"info","ts":1730721600.1,"logger":"tls.cache.maintenance","msg":"started background certificate maintenance"}`

	nginxLine    = `203.0.113.9 - - [04/Nov/2024:12:00:00 +0000] "GET /products/blue-widget?fbclid=IwAR2x HTTP/1.1" 200 48213 "https://m.facebook.com/" "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X)"`
	nginxEscaped = `203.0.113.9 - - [04/Nov/2024:12:00:02 +0000] "GET /search?q=\x22boots\x22 HTTP/1.1" 200 931 "-" "curl/8.5.0"`
	nginxJunk    = `203.0.113.9 - - [04/Nov/2024:12:00:03 +0000] "\x16\x03\x01\x02\x00\x01\x00\x01\xFC\x03\x03" 400 157 "-" "-"`
)

func scanAll(t *testing.T, path string, opts Options) ([]Record, *Scanner) {
	t.Helper()
	s := Open([]string{path}, opts)
	defer s.Close()
	var out []Record
	for s.Scan() {
		out = append(out, *s.Record())
	}
	if err := s.Err(); err != nil {
		t.Fatalf("scan: %v", err)
	}
	return out, s
}

func writeFile(t *testing.T, name, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestCloudflare(t *testing.T) {
	p := writeFile(t, "cf.json", cfLineHit+"\n\n"+cfLineRFC+"\n")
	recs, s := scanAll(t, p, Options{})
	if len(recs) != 2 || s.Skipped != 0 {
		t.Fatalf("got %d records, %d skipped: %v", len(recs), s.Skipped, s.Errors)
	}
	r := recs[0]
	if r.Host != "shop.example.com" || r.Path != "/products/blue-widget" || r.RawQuery != "utm_source=newsletter&color=blue" {
		t.Errorf("url parts wrong: %+v", r)
	}
	if r.Bytes != 47702 {
		t.Errorf("want body bytes 47702, got %d", r.Bytes)
	}
	if r.CacheStatus != "hit" || r.Status != 200 || r.Scheme != "https" {
		t.Errorf("status fields wrong: %+v", r)
	}
	if want := time.Unix(0, 1730721600123456789).UTC(); !r.Time.Equal(want) {
		t.Errorf("time %v, want %v", r.Time, want)
	}
	if r.Header["user-agent"] == "" || r.Cookies["currency"] != "EUR" {
		t.Errorf("headers/cookies missing: %v %v", r.Header, r.Cookies)
	}

	r = recs[1]
	if r.Path != "/static/app.js" || r.Bytes != 1200 || r.Time.Year() != 2024 {
		t.Errorf("second line wrong: %+v", r)
	}
}

func TestCaddy(t *testing.T) {
	p := writeFile(t, "access.log", strings.Join([]string{caddyRuntime, caddyLineTLS, caddyLineCookie}, "\n"))
	recs, s := scanAll(t, p, Options{})
	if len(recs) != 2 {
		t.Fatalf("got %d records: %v", len(recs), s.Errors)
	}
	if s.Skipped != 1 || len(s.Errors) != 0 {
		t.Errorf("runtime log line should be skipped quietly, skipped=%d errors=%v", s.Skipped, s.Errors)
	}
	r := recs[0]
	if r.Scheme != "https" || r.Host != "shop.example.com" || r.RawQuery != "q=boots&page=2" {
		t.Errorf("parts wrong: %+v", r)
	}
	if r.Cookies != nil {
		t.Errorf("redacted cookie should not produce cookies, got %v", r.Cookies)
	}
	if r.CacheStatus != "hit" || r.Bytes != 10900 {
		t.Errorf("cache status/bytes wrong: %+v", r)
	}
	r = recs[1]
	if r.Scheme != "http" || r.CacheStatus != "miss" {
		t.Errorf("second record: %+v", r)
	}
	if r.Cookies["currency"] != "EUR" || r.Cookies["theme"] != "dark" {
		t.Errorf("cookies: %v", r.Cookies)
	}
	if r.Header["accept-language"] != "de-DE,de;q=0.9" {
		t.Errorf("headers: %v", r.Header)
	}
}

func TestNginxCombined(t *testing.T) {
	p := writeFile(t, "access.log", nginxLine+"\n"+nginxEscaped+"\n"+nginxJunk+"\n")
	recs, s := scanAll(t, p, Options{DefaultHost: "shop.example.com"})
	if len(recs) != 2 || s.Skipped != 1 {
		t.Fatalf("records=%d skipped=%d errors=%v", len(recs), s.Skipped, s.Errors)
	}
	r := recs[0]
	if r.Host != "shop.example.com" || r.Method != "GET" || r.RawQuery != "fbclid=IwAR2x" || r.Bytes != 48213 {
		t.Errorf("parts wrong: %+v", r)
	}
	if !strings.Contains(r.Header["user-agent"], "iPhone") || r.Header["referer"] != "https://m.facebook.com/" {
		t.Errorf("headers wrong: %v", r.Header)
	}
	if r.Time.Hour() != 12 {
		t.Errorf("time %v", r.Time)
	}
	if got := recs[1].RawQuery; got != `q="boots"` {
		t.Errorf("escaped query = %q", got)
	}
}

func TestNginxCustomFormat(t *testing.T) {
	format := `$remote_addr [$time_iso8601] $host "$request" $status $bytes_sent $upstream_cache_status "$http_accept_language" "$cookie_currency" $request_time`
	line := `198.51.100.7 [2024-11-04T12:00:00+00:00] shop.example.com "GET /p/42?color=red HTTP/2.0" 200 5120 HIT "en-GB,en;q=0.8" "GBP" 0.004`
	p := writeFile(t, "a.log", line+"\n")
	recs, s := scanAll(t, p, Options{Format: Nginx, NginxFormat: format})
	if len(recs) != 1 {
		t.Fatalf("no record: %v", s.Errors)
	}
	r := recs[0]
	if r.Host != "shop.example.com" || r.CacheStatus != "hit" || r.Bytes != 5120 {
		t.Errorf("parts wrong: %+v", r)
	}
	if r.Header["accept-language"] != "en-GB,en;q=0.8" || r.Cookies["currency"] != "GBP" {
		t.Errorf("header/cookie: %v %v", r.Header, r.Cookies)
	}
}

func TestNginxFormatErrors(t *testing.T) {
	for _, f := range []string{
		`$remote_addr $status`, // nothing to key on
		`$request$status`,      // adjacent variables
		`${request "$status"`,  // unterminated brace
	} {
		if _, err := newNginxParser(f); err == nil {
			t.Errorf("format %q: expected an error", f)
		}
	}
}

func TestGzipAndMultipleFiles(t *testing.T) {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	zw.Write([]byte(nginxLine + "\n"))
	zw.Close()
	dir := t.TempDir()
	gz := filepath.Join(dir, "access.log.1.gz")
	os.WriteFile(gz, buf.Bytes(), 0o644)
	plain := filepath.Join(dir, "cf.json")
	os.WriteFile(plain, []byte(cfLineHit+"\n"), 0o644)

	s := Open([]string{gz, plain}, Options{})
	var hosts []string
	for s.Scan() {
		hosts = append(hosts, s.Record().Host)
	}
	if s.Err() != nil {
		t.Fatal(s.Err())
	}
	// first file has no host field, second does. each file gets its own
	// format sniffing.
	if len(hosts) != 2 || hosts[0] != "" || hosts[1] != "shop.example.com" {
		t.Errorf("hosts = %q", hosts)
	}
}

func TestSetURI(t *testing.T) {
	cases := []struct {
		in, path, query, host string
	}{
		{"/a/b?x=1&y=2", "/a/b", "x=1&y=2", ""},
		{"/a#frag", "/a", "", ""},
		{"", "/", "", ""},
		{"?x=1", "/", "x=1", ""},
		{"http://Origin.Internal:8080/p?q", "/p", "q", "origin.internal"},
		{"https://example.com", "/", "", "example.com"},
	}
	for _, c := range cases {
		var r Record
		r.setURI(c.in)
		if r.Path != c.path || r.RawQuery != c.query || r.Host != c.host {
			t.Errorf("setURI(%q) = %q %q %q", c.in, r.Path, r.RawQuery, r.Host)
		}
	}
}

func TestCleanHost(t *testing.T) {
	for in, want := range map[string]string{
		"Example.COM:443": "example.com",
		"example.com.":    "example.com",
		"[::1]:8080":      "[::1]",
		"-":               "",
	} {
		if got := cleanHost(in); got != want {
			t.Errorf("cleanHost(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestParseUnixNumber(t *testing.T) {
	want := time.Date(2024, 11, 4, 12, 0, 0, 0, time.UTC)
	for _, s := range []string{"1730721600", "1730721600000", "1730721600000000", "1730721600000000000", "1730721600.0"} {
		got, err := parseUnixNumber(s)
		if err != nil || !got.Equal(want) {
			t.Errorf("parseUnixNumber(%s) = %v, %v", s, got, err)
		}
	}
}

func FuzzNginxLine(f *testing.F) {
	f.Add(nginxLine)
	f.Add(nginxEscaped)
	f.Add(nginxJunk)
	f.Add(`- - - [] "" - - "" ""`)
	p, err := newNginxParser("")
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, line string) {
		var r Record
		if p.parse([]byte(line), &r) == nil && r.Path == "" {
			t.Errorf("parsed %q without a path", line)
		}
	})
}

func FuzzJSONLines(f *testing.F) {
	f.Add(cfLineHit)
	f.Add(caddyLineTLS)
	f.Add(caddyLineCookie)
	f.Fuzz(func(t *testing.T, line string) {
		var r Record
		cloudflareParser{}.parse([]byte(line), &r)
		r = Record{}
		caddyParser{}.parse([]byte(line), &r)
	})
}

func benchParse(b *testing.B, p lineParser, line string) {
	b.SetBytes(int64(len(line)))
	b.ReportAllocs()
	raw := []byte(line)
	for i := 0; i < b.N; i++ {
		var r Record
		if err := p.parse(raw, &r); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkCloudflare(b *testing.B) { benchParse(b, cloudflareParser{}, cfLineHit) }
func BenchmarkCaddy(b *testing.B)      { benchParse(b, caddyParser{}, caddyLineTLS) }
func BenchmarkNginx(b *testing.B) {
	p, _ := newNginxParser("")
	benchParse(b, p, nginxLine)
}
