package logs

import (
	"encoding/json"
	"errors"
	"strings"
)

// caddy's access log, one json object per line. the shape has been stable
// since 2.0; resp_headers and client_ip arrived later and are optional here.
type caddyLine struct {
	Logger  string          `json:"logger"`
	TS      json.RawMessage `json:"ts"`
	Request *struct {
		Method  string              `json:"method"`
		Host    string              `json:"host"`
		URI     string              `json:"uri"`
		Proto   string              `json:"proto"`
		Headers map[string][]string `json:"headers"`
		TLS     json.RawMessage     `json:"tls"`
	} `json:"request"`
	Status      int                 `json:"status"`
	Size        int64               `json:"size"`
	RespHeaders map[string][]string `json:"resp_headers"`
}

// what caddy writes in place of cookie and authorization values unless
// log_credentials is on.
const caddyRedacted = "REDACTED"

var errNotAccessLine = errors.New("not an access log entry")

type caddyParser struct{}

func (caddyParser) parse(line []byte, rec *Record) error {
	var l caddyLine
	if err := json.Unmarshal(line, &l); err != nil {
		return err
	}
	// caddy happily writes its own runtime logs into the same file when the
	// log block isn't split, so skip anything that isn't a request.
	if l.Request == nil || l.Request.URI == "" {
		return errNotAccessLine
	}
	ts, err := parseFlexTime(l.TS)
	if err != nil {
		return err
	}
	rec.Time = ts
	rec.Method = strings.ToUpper(l.Request.Method)
	rec.Scheme = "http"
	if len(l.Request.TLS) > 0 && string(l.Request.TLS) != "null" {
		rec.Scheme = "https"
	}
	rec.Host = cleanHost(l.Request.Host)
	rec.setURI(l.Request.URI)
	rec.Status = l.Status
	rec.Bytes = l.Size

	if len(l.Request.Headers) > 0 {
		rec.Header = make(map[string]string, len(l.Request.Headers))
		for k, vs := range l.Request.Headers {
			if len(vs) == 0 {
				continue
			}
			name := strings.ToLower(k)
			if name == "cookie" {
				if vs[0] != caddyRedacted {
					rec.Cookies = parseCookieHeader(strings.Join(vs, "; "))
				}
				continue
			}
			rec.Header[name] = strings.Join(vs, ", ")
		}
	}
	rec.CacheStatus = caddyCacheStatus(l.RespHeaders)
	return nil
}

// pulls a hit/miss out of whatever cache headers the response carried. the
// cache-handler module writes an rfc 9211 cache-status header like
// "souin; hit; ttl=12" or "souin; fwd=uri-miss".
func caddyCacheStatus(h map[string][]string) string {
	for k, vs := range h {
		if len(vs) == 0 {
			continue
		}
		switch strings.ToLower(k) {
		case "cache-status":
			v := strings.ToLower(vs[0])
			switch {
			case strings.Contains(v, "; hit"):
				return "hit"
			case strings.Contains(v, "fwd=stale"):
				return "expired"
			case strings.Contains(v, "fwd=bypass"), strings.Contains(v, "fwd=request"):
				return "bypass"
			case strings.Contains(v, "fwd="):
				return "miss"
			}
		case "x-cache", "x-cache-status":
			v := strings.ToLower(vs[0])
			switch {
			case strings.Contains(v, "hit"):
				return "hit"
			case strings.Contains(v, "miss"):
				return "miss"
			}
		}
	}
	return ""
}
