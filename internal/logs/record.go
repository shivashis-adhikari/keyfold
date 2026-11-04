// package logs turns cdn and web server access logs into a common record type.
package logs

import (
	"fmt"
	"strings"
	"time"
)

// one request pulled out of an access log. fields that a format doesn't
// carry stay at their zero value.
type Record struct {
	Time     time.Time
	Method   string
	Scheme   string
	Host     string // lowercased, port stripped
	Path     string // raw path as sent, still percent-encoded
	RawQuery string // raw query without the leading '?'
	Status   int
	Bytes    int64 // response bytes sent to the client

	// cache status as the cdn or proxy reported it ("hit", "miss", ...).
	// empty when the log doesn't say.
	CacheStatus string

	// request headers and cookies, only when the log carried them. header
	// names are lowercased.
	Header  map[string]string
	Cookies map[string]string
}

// path and query the way they appeared on the request line.
func (r *Record) URI() string {
	if r.RawQuery == "" {
		return r.Path
	}
	return r.Path + "?" + r.RawQuery
}

// splits a request target into path and query. absolute-form targets
// ("get http://host/path") show up in proxy logs, so scheme and host get
// pulled out of those too.
func (r *Record) setURI(uri string) {
	if i := strings.Index(uri, "://"); i > 0 && i < 8 {
		rest := uri[i+3:]
		if r.Scheme == "" {
			r.Scheme = strings.ToLower(uri[:i])
		}
		slash := strings.IndexByte(rest, '/')
		if slash < 0 {
			if r.Host == "" {
				r.Host = cleanHost(rest)
			}
			uri = "/"
		} else {
			if r.Host == "" {
				r.Host = cleanHost(rest[:slash])
			}
			uri = rest[slash:]
		}
	}
	// fragments never reach the server, but broken clients do send them
	if i := strings.IndexByte(uri, '#'); i >= 0 {
		uri = uri[:i]
	}
	if i := strings.IndexByte(uri, '?'); i >= 0 {
		r.Path, r.RawQuery = uri[:i], uri[i+1:]
	} else {
		r.Path, r.RawQuery = uri, ""
	}
	if r.Path == "" {
		r.Path = "/"
	}
}

func cleanHost(h string) string {
	h = strings.ToLower(strings.TrimSpace(h))
	if h == "" || h == "-" {
		return ""
	}
	if strings.HasPrefix(h, "[") {
		// ipv6 literal, keep the brackets and drop the port
		if i := strings.IndexByte(h, ']'); i > 0 {
			return h[:i+1]
		}
		return h
	}
	if i := strings.LastIndexByte(h, ':'); i >= 0 && strings.Count(h, ":") == 1 {
		h = h[:i]
	}
	return strings.TrimSuffix(h, ".")
}

// reads a cookie request header. lenient on purpose, real traffic is full
// of malformed pairs.
func parseCookieHeader(v string) map[string]string {
	if v == "" {
		return nil
	}
	out := make(map[string]string)
	for _, part := range strings.Split(v, ";") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		name, val, _ := strings.Cut(part, "=")
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		out[name] = strings.Trim(strings.TrimSpace(val), `"`)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// which access log dialect a file is in.
type Format int

const (
	Auto Format = iota
	Cloudflare
	Caddy
	Nginx
)

func (f Format) String() string {
	switch f {
	case Cloudflare:
		return "cloudflare"
	case Caddy:
		return "caddy"
	case Nginx:
		return "nginx"
	}
	return "auto"
}

// maps a command line value to a format.
func ParseFormat(s string) (Format, error) {
	switch strings.ToLower(s) {
	case "", "auto":
		return Auto, nil
	case "cloudflare", "cf", "logpush":
		return Cloudflare, nil
	case "caddy":
		return Caddy, nil
	case "nginx", "combined":
		return Nginx, nil
	}
	return Auto, fmt.Errorf("unknown log format %q (want auto, cloudflare, caddy or nginx)", s)
}
