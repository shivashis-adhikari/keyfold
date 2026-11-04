package normalize

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"
)

var fixedNow = time.Date(2024, 11, 4, 12, 0, 0, 0, time.UTC)

func newN(t *testing.T, extra ...string) *Normalizer {
	t.Helper()
	n, err := New(extra)
	if err != nil {
		t.Fatal(err)
	}
	n.SetClock(func() time.Time { return fixedNow })
	return n
}

func page(nonce, csrf, ts, body string) string {
	return fmt.Sprintf(`<!doctype html><html><head>
<meta name="csrf-token" content="%s">
<script nonce="%s">window.x=1</script></head>
<body><!-- rendered in 12ms on web-3 -->
<p>%s</p>
<form><input type="hidden" name="authenticity_token" value="%s"></form>
<footer>generated %s</footer></body></html>`, csrf, nonce, body, csrf, ts)
}

func TestHTMLMasksPerRequestNoise(t *testing.T) {
	n := newN(t)
	a := n.Body("text/html; charset=utf-8", []byte(page("r4nd0m", "tok-a", "2024-11-04T11:59:58Z", "blue widget")))
	b := n.Body("text/html", []byte(page("0th3r", "tok-b", "2024-11-04 12:00:03+00:00", "blue widget")))
	if Hash(a) != Hash(b) {
		t.Errorf("same page with different nonce/csrf/timestamp should hash equal\n%s\n---\n%s", a, b)
	}
	c := n.Body("text/html", []byte(page("r4nd0m", "tok-a", "2024-11-04T11:59:58Z", "red widget")))
	if Hash(a) == Hash(c) {
		t.Errorf("different content must not hash equal")
	}
}

func TestOldDatesAreContent(t *testing.T) {
	n := newN(t)
	// a publish date from last year is content, not a clock
	a := n.Body("text/html", []byte("<time>2023-01-15T09:00:00Z</time>"))
	b := n.Body("text/html", []byte("<time>2023-01-16T09:00:00Z</time>"))
	if Hash(a) == Hash(b) {
		t.Error("dates far from now should not be masked")
	}
}

func TestJSON(t *testing.T) {
	n := newN(t)
	a := n.Body("application/json", []byte(`{"items":[{"id":1,"name":"widget"}],"request_id":"9f1c","server_time":1730721600,"meta":{"took_ms":12,"ts":1730721601234}}`))
	b := n.Body("application/json; charset=utf-8", []byte(`{"meta":{"ts":1730721605000,"took_ms":7},"server_time":1730721603,"request_id":"77aa","items":[{"name":"widget","id":1}]}`))
	if string(a) != string(b) {
		t.Errorf("json should normalise to the same bytes:\n%s\n%s", a, b)
	}
	c := n.Body("application/json", []byte(`{"items":[{"id":2,"name":"widget"}],"request_id":"9f1c"}`))
	if Hash(a) == Hash(c) {
		t.Error("different ids must differ")
	}
	// broken json falls back to text instead of failing
	if got := n.Body("application/json", []byte(`{"a":`)); string(got) != `{"a":` {
		t.Errorf("got %q", got)
	}
}

func TestExtraPatterns(t *testing.T) {
	n := newN(t, `build [0-9a-f]+`)
	a := n.Body("text/plain", []byte("ok build 3f9c2a"))
	b := n.Body("text/plain", []byte("ok build 77aa01"))
	if Hash(a) != Hash(b) {
		t.Error("extra pattern not applied")
	}
	if _, err := New([]string{"("}); err == nil {
		t.Error("bad regex should error")
	}
}

func TestBinaryUntouched(t *testing.T) {
	n := newN(t)
	png := []byte("\x89PNG\r\n\x1a\n<!-- not a comment --> 1730721600")
	if got := n.Body("image/png", png); string(got) != string(png) {
		t.Error("binary bodies must not be rewritten")
	}
}

func TestFingerprintDiff(t *testing.T) {
	n := newN(t)
	h := http.Header{"Content-Type": {"text/html"}, "Content-Language": {"en"}}
	a, _ := n.Fingerprint(h, 200, []byte("hello"))
	h2 := h.Clone()
	h2.Set("Content-Language", "de")
	b, _ := n.Fingerprint(h2, 200, []byte("hello"))
	if d := a.Diff(b); !strings.Contains(d, "content-language") {
		t.Errorf("diff = %q", d)
	}
	c, _ := n.Fingerprint(h, 404, []byte("hello"))
	if d := a.Diff(c); !strings.Contains(d, "status") {
		t.Errorf("diff = %q", d)
	}
	if a.Diff(a) != "" || !a.SameMeta(a) {
		t.Error("fingerprint should equal itself")
	}
}

func TestVolatileRotation(t *testing.T) {
	// a "deal of the hour" block rotates between identical requests. the
	// colour is what the param changes.
	base := func(deal, colour string) Tokens {
		return Tokenize([]byte(fmt.Sprintf("<h1>%s widget</h1><aside>deal: %s</aside><p>in stock</p>", colour, deal)))
	}
	var v Volatile
	v.Add(base("socks", "blue"))
	v.Add(base("hats", "blue"))
	v.Add(base("socks", "blue"))

	if r := v.Residual(base("hats", "blue"), 0); len(r) != 0 {
		t.Errorf("rotation seen during baselines should be noise, residual=%v", r)
	}
	if r := v.Residual(base("socks", "red"), 0); len(r) == 0 {
		t.Error("colour change must survive the volatile filter")
	}
	// a deal we never saw rotate in is reported. that's the conservative
	// side of the trade-off.
	if r := v.Residual(base("scarves", "blue"), 0); len(r) == 0 {
		t.Error("unseen rotation should be reported")
	}
}
