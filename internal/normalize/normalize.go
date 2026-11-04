// package normalize turns http responses into something you can compare:
// a fingerprint of the parts a cache key decision cares about, with the
// obviously per-request bits (nonces, csrf tokens, request ids, timestamps
// close to now) masked out of the body.
//
// masking is deliberately light. anything else that wobbles between two
// identical requests is caught by comparing against repeated baselines
// (see tokendiff.go) instead of guessing with more regexes, because every
// extra mask is a chance to hide a real difference.
package normalize

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"mime"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type Normalizer struct {
	extra []*regexp.Regexp
	now   func() time.Time
	// timestamps within this distance of now count as "generated now"
	window time.Duration
}

// extra is a list of regular expressions whose matches get blanked before
// hashing, for site-specific noise the defaults miss.
func New(extra []string) (*Normalizer, error) {
	n := &Normalizer{now: time.Now, window: 72 * time.Hour}
	for _, e := range extra {
		re, err := regexp.Compile(e)
		if err != nil {
			return nil, fmt.Errorf("ignore pattern %q: %w", e, err)
		}
		n.extra = append(n.extra, re)
	}
	return n, nil
}

// sets the clock used for "near now" checks. tests only.
func (n *Normalizer) SetClock(now func() time.Time) { n.now = now }

var (
	htmlComment = regexp.MustCompile(`(?s)<!--.*?-->`)
	nonceAttr   = regexp.MustCompile(`\bnonce="[^"]*"`)
	formTag     = regexp.MustCompile(`(?i)<(?:input|meta)\b[^>]*>`)
	csrfName    = regexp.MustCompile(`(?i)(csrf|xsrf|authenticity_token|_token\b|requestverificationtoken|csrfmiddlewaretoken)`)
	valueAttr   = regexp.MustCompile(`(?i)\b(value|content)="[^"]*"`)
	isoTime     = regexp.MustCompile(`\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}(?::\d{2}(?:\.\d+)?)?(?:Z|[+-]\d{2}:?\d{2})?`)
	httpDate    = regexp.MustCompile(`\b(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun), \d{2} (?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) \d{4} \d{2}:\d{2}:\d{2} GMT\b`)
	epochNum    = regexp.MustCompile(`\b1\d{9}(?:\d{3})?(?:\.\d+)?\b`)

	volatileKey = regexp.MustCompile(`(?i)^_?(request_?id|req_?id|trace_?id|span_?id|correlation_?id|nonce|csrf(_?token)?|xsrf(_?token)?|server_?time|generated_?at|rendered_?at|took(_?ms)?|elapsed(_?ms)?|duration(_?ms)?|latency(_?ms)?|response_?time(_?ms)?)$`)
)

const mask = "\x00"

// returns the normalised body. images, fonts and other binary types are
// returned unchanged.
func (n *Normalizer) Body(contentType string, body []byte) []byte {
	mt := mediaType(contentType)
	switch {
	case isBinary(mt):
		return body
	case strings.Contains(mt, "json"):
		if out, ok := n.json(body); ok {
			return out
		}
	}
	return n.text(body)
}

func (n *Normalizer) text(b []byte) []byte {
	b = htmlComment.ReplaceAll(b, nil)
	b = nonceAttr.ReplaceAll(b, []byte(`nonce=""`))
	b = formTag.ReplaceAllFunc(b, func(tag []byte) []byte {
		if !csrfName.Match(tag) {
			return tag
		}
		return valueAttr.ReplaceAll(tag, []byte(`$1=""`))
	})
	b = n.maskTimes(b)
	for _, re := range n.extra {
		b = re.ReplaceAll(b, []byte(mask))
	}
	return b
}

func (n *Normalizer) maskTimes(b []byte) []byte {
	now := n.now()
	near := func(t time.Time) bool {
		d := t.Sub(now)
		return d < n.window && d > -n.window
	}
	b = isoTime.ReplaceAllFunc(b, func(m []byte) []byte {
		s := strings.Replace(string(m), " ", "T", 1)
		for _, layout := range []string{time.RFC3339Nano, "2006-01-02T15:04:05Z0700", "2006-01-02T15:04:05", "2006-01-02T15:04"} {
			if t, err := time.Parse(layout, s); err == nil {
				if near(t) {
					return []byte(mask)
				}
				return m
			}
		}
		return m
	})
	b = httpDate.ReplaceAllFunc(b, func(m []byte) []byte {
		if t, err := http.ParseTime(string(m)); err == nil && near(t) {
			return []byte(mask)
		}
		return m
	})
	b = epochNum.ReplaceAllFunc(b, func(m []byte) []byte {
		if t, ok := epochTime(string(m)); ok && near(t) {
			return []byte(mask)
		}
		return m
	})
	return b
}

func epochTime(s string) (time.Time, bool) {
	f, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return time.Time{}, false
	}
	if f > 1e11 {
		return time.UnixMilli(int64(f)), true
	}
	return time.Unix(int64(f), 0), true
}

func (n *Normalizer) json(b []byte) ([]byte, bool) {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, false
	}
	if dec.More() {
		return nil, false // ndjson or trailing junk, treat as text
	}
	v = n.walk(v)
	out, err := json.Marshal(v) // maps come out with sorted keys
	if err != nil {
		return nil, false
	}
	return out, true
}

func (n *Normalizer) walk(v any) any {
	switch x := v.(type) {
	case map[string]any:
		for k, val := range x {
			if volatileKey.MatchString(k) {
				x[k] = mask
				continue
			}
			x[k] = n.walk(val)
		}
		return x
	case []any:
		for i := range x {
			x[i] = n.walk(x[i])
		}
		return x
	case string:
		return string(n.text([]byte(x)))
	case json.Number:
		if t, ok := epochTime(x.String()); ok && len(x.String()) >= 10 {
			d := t.Sub(n.now())
			if d < n.window && d > -n.window {
				return mask
			}
		}
		return x
	}
	return v
}

func mediaType(ct string) string {
	if ct == "" {
		return ""
	}
	mt, _, err := mime.ParseMediaType(ct)
	if err != nil {
		return strings.ToLower(strings.TrimSpace(strings.Split(ct, ";")[0]))
	}
	return mt
}

func isBinary(mt string) bool {
	switch {
	case strings.HasPrefix(mt, "image/"), strings.HasPrefix(mt, "video/"), strings.HasPrefix(mt, "audio/"),
		strings.HasPrefix(mt, "font/"), mt == "application/octet-stream", mt == "application/pdf",
		mt == "application/zip", mt == "application/wasm":
		return true
	}
	return false
}

// a short stable hash of a normalised body.
func Hash(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:12])
}

// the parts of a response that decide whether two requests may share a
// cache entry. headers outside this list (date, age, server timing, ...)
// differ on every request and say nothing about content.
type Fingerprint struct {
	Status   int    `json:"status"`
	Type     string `json:"type,omitempty"`
	Location string `json:"location,omitempty"`
	Language string `json:"language,omitempty"`
	CORS     string `json:"cors,omitempty"`
	Body     string `json:"body"`
	Size     int    `json:"size"`
}

// normalises a response body and fingerprints it. it also
// returns the normalised body, which callers keep for token diffs.
func (n *Normalizer) Fingerprint(h http.Header, status int, body []byte) (Fingerprint, []byte) {
	norm := n.Body(h.Get("Content-Type"), body)
	return Fingerprint{
		Status:   status,
		Type:     mediaType(h.Get("Content-Type")),
		Location: h.Get("Location"),
		Language: strings.ToLower(h.Get("Content-Language")),
		CORS:     h.Get("Access-Control-Allow-Origin"),
		Body:     Hash(norm),
		Size:     len(body),
	}, norm
}

// describes the first difference between two fingerprints, or returns
// "" when they match. size is ignored, the body hash covers it.
func (f Fingerprint) Diff(o Fingerprint) string {
	switch {
	case f.Status != o.Status:
		return fmt.Sprintf("status %d vs %d", f.Status, o.Status)
	case f.Location != o.Location:
		return fmt.Sprintf("location %q vs %q", f.Location, o.Location)
	case f.Type != o.Type:
		return fmt.Sprintf("content-type %s vs %s", f.Type, o.Type)
	case f.Language != o.Language:
		return fmt.Sprintf("content-language %q vs %q", f.Language, o.Language)
	case f.CORS != o.CORS:
		return fmt.Sprintf("access-control-allow-origin %q vs %q", f.CORS, o.CORS)
	case f.Body != o.Body:
		return "body differs"
	}
	return ""
}

// true when everything but the body matches.
func (f Fingerprint) SameMeta(o Fingerprint) bool {
	o.Body, o.Size = f.Body, f.Size
	return f.Diff(o) == ""
}
