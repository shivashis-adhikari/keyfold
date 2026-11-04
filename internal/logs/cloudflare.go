package logs

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// the logpush http_requests fields we care about. logpush lets you pick
// fields per job, so any of these can be missing.
type cfLine struct {
	ClientRequestHost      string            `json:"ClientRequestHost"`
	ClientRequestMethod    string            `json:"ClientRequestMethod"`
	ClientRequestURI       string            `json:"ClientRequestURI"`
	ClientRequestPath      string            `json:"ClientRequestPath"`
	ClientRequestScheme    string            `json:"ClientRequestScheme"`
	ClientRequestUserAgent string            `json:"ClientRequestUserAgent"`
	ClientRequestReferer   string            `json:"ClientRequestReferer"`
	EdgeStartTimestamp     json.RawMessage   `json:"EdgeStartTimestamp"`
	EdgeResponseStatus     int               `json:"EdgeResponseStatus"`
	EdgeResponseBytes      int64             `json:"EdgeResponseBytes"`
	EdgeResponseBodyBytes  int64             `json:"EdgeResponseBodyBytes"`
	CacheCacheStatus       string            `json:"CacheCacheStatus"`
	RequestHeaders         map[string]string `json:"RequestHeaders"`
	Cookies                map[string]string `json:"Cookies"`
}

type cloudflareParser struct{}

func (cloudflareParser) parse(line []byte, rec *Record) error {
	var l cfLine
	if err := json.Unmarshal(line, &l); err != nil {
		return err
	}
	if l.ClientRequestURI == "" && l.ClientRequestPath == "" {
		return errors.New("no ClientRequestURI or ClientRequestPath field")
	}
	ts, err := parseFlexTime(l.EdgeStartTimestamp)
	if err != nil {
		return fmt.Errorf("EdgeStartTimestamp: %w", err)
	}
	rec.Time = ts
	rec.Method = strings.ToUpper(l.ClientRequestMethod)
	rec.Scheme = strings.ToLower(l.ClientRequestScheme)
	rec.Host = cleanHost(l.ClientRequestHost)
	if l.ClientRequestURI != "" {
		rec.setURI(l.ClientRequestURI)
	} else {
		rec.setURI(l.ClientRequestPath)
	}
	rec.Status = l.EdgeResponseStatus
	// body bytes is what the origin would have had to send. the total
	// includes edge headers, which don't move between keys.
	rec.Bytes = l.EdgeResponseBodyBytes
	if rec.Bytes == 0 {
		rec.Bytes = l.EdgeResponseBytes
	}
	rec.CacheStatus = strings.ToLower(l.CacheCacheStatus)

	if l.ClientRequestUserAgent != "" || l.ClientRequestReferer != "" || len(l.RequestHeaders) > 0 {
		rec.Header = make(map[string]string, len(l.RequestHeaders)+2)
		for k, v := range l.RequestHeaders {
			rec.Header[strings.ToLower(k)] = v
		}
		if l.ClientRequestUserAgent != "" {
			rec.Header["user-agent"] = l.ClientRequestUserAgent
		}
		if l.ClientRequestReferer != "" {
			rec.Header["referer"] = l.ClientRequestReferer
		}
	}
	if len(l.Cookies) > 0 {
		rec.Cookies = l.Cookies
	}
	return nil
}

// reads the timestamp shapes logpush and caddy can emit:
// unix seconds as int or float, unix ms/us/ns as int, rfc3339 strings, or
// numbers inside strings.
func parseFlexTime(raw json.RawMessage) (time.Time, error) {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || string(raw) == "null" {
		return time.Time{}, nil
	}
	if raw[0] == '"' {
		var s string
		if err := json.Unmarshal(raw, &s); err != nil {
			return time.Time{}, err
		}
		return parseTimeString(s)
	}
	return parseUnixNumber(string(raw))
}

func parseTimeString(s string) (time.Time, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}, nil
	}
	if c := s[0]; c >= '0' && c <= '9' && !strings.ContainsAny(s, "-:T/") {
		return parseUnixNumber(s)
	}
	for _, layout := range []string{
		time.RFC3339Nano,
		"2006-01-02T15:04:05.999999999Z0700",
		"2006/01/02 15:04:05.000",
		"2006-01-02 15:04:05.999999999",
		"02/Jan/2006:15:04:05 -0700",
	} {
		if t, err := time.Parse(layout, s); err == nil {
			return t, nil
		}
	}
	return time.Time{}, fmt.Errorf("unrecognised timestamp %q", s)
}

func parseUnixNumber(s string) (time.Time, error) {
	if strings.ContainsAny(s, ".eE") {
		f, err := strconv.ParseFloat(s, 64)
		if err != nil {
			return time.Time{}, err
		}
		sec := int64(f)
		return time.Unix(sec, int64((f-float64(sec))*1e9)).UTC(), nil
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return time.Time{}, err
	}
	// guess the unit from the magnitude. anything after 2001 in seconds is
	// at least 1e9, so these cut-offs don't overlap for real dates.
	switch {
	case n > 1e17:
		return time.Unix(0, n).UTC(), nil
	case n > 1e14:
		return time.UnixMicro(n).UTC(), nil
	case n > 1e11:
		return time.UnixMilli(n).UTC(), nil
	}
	return time.Unix(n, 0).UTC(), nil
}
