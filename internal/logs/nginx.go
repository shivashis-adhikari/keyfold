package logs

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// nginx's built-in "combined" log_format.
const CombinedFormat = `$remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent"`

// a compiled log_format is a list of literal and variable pieces. matching
// walks the line once: a variable runs until the next literal shows up. that
// is the same assumption nginx's own escaping makes safe, since quotes inside
// values get written as \x22.
type nginxPiece struct {
	lit string // set for literal pieces
	v   string // variable name, without the '$'
}

type nginxParser struct {
	pieces []nginxPiece
}

func newNginxParser(format string) (*nginxParser, error) {
	if strings.TrimSpace(format) == "" {
		format = CombinedFormat
	}
	var pieces []nginxPiece
	var lit strings.Builder
	flush := func() {
		if lit.Len() > 0 {
			pieces = append(pieces, nginxPiece{lit: lit.String()})
			lit.Reset()
		}
	}
	for i := 0; i < len(format); {
		c := format[i]
		if c != '$' {
			lit.WriteByte(c)
			i++
			continue
		}
		// $name or ${name}
		j := i + 1
		braced := j < len(format) && format[j] == '{'
		if braced {
			j++
		}
		start := j
		for j < len(format) && isVarChar(format[j]) {
			j++
		}
		if j == start {
			lit.WriteByte(c)
			i++
			continue
		}
		name := format[start:j]
		if braced {
			if j >= len(format) || format[j] != '}' {
				return nil, fmt.Errorf("log format: unterminated ${%s", name)
			}
			j++
		}
		flush()
		if n := len(pieces); n > 0 && pieces[n-1].lit == "" {
			return nil, fmt.Errorf("log format: $%s directly follows $%s, can't split them", name, pieces[n-1].v)
		}
		pieces = append(pieces, nginxPiece{v: name})
		i = j
	}
	flush()

	p := &nginxParser{pieces: pieces}
	if !p.has("request", "request_uri", "uri") {
		return nil, errors.New("log format has none of $request, $request_uri or $uri, nothing to key on")
	}
	return p, nil
}

func isVarChar(c byte) bool {
	return c == '_' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
}

func (p *nginxParser) has(names ...string) bool {
	for _, pc := range p.pieces {
		for _, n := range names {
			if pc.v == n {
				return true
			}
		}
	}
	return false
}

var errLineShape = errors.New("line doesn't match log format")

func (p *nginxParser) parse(line []byte, rec *Record) error {
	s := string(line)
	pos := 0
	var uri, args string
	var bodyBytes, allBytes int64 = -1, -1
	for i, pc := range p.pieces {
		if pc.lit != "" {
			if !strings.HasPrefix(s[pos:], pc.lit) {
				return errLineShape
			}
			pos += len(pc.lit)
			continue
		}
		end := len(s)
		if i+1 < len(p.pieces) {
			k := strings.Index(s[pos:], p.pieces[i+1].lit)
			if k < 0 {
				return errLineShape
			}
			end = pos + k
		}
		val := s[pos:end]
		pos = end
		if val == "-" {
			continue
		}
		if strings.Contains(val, `\x`) {
			val = unescapeNginx(val)
		}
		if err := p.assign(rec, pc.v, val, &uri, &args, &bodyBytes, &allBytes); err != nil {
			return fmt.Errorf("$%s: %w", pc.v, err)
		}
	}
	if uri == "" {
		return errors.New("no request uri in line")
	}
	rec.setURI(uri)
	if args != "" && rec.RawQuery == "" {
		rec.RawQuery = args
	}
	switch {
	case bodyBytes >= 0:
		rec.Bytes = bodyBytes
	case allBytes >= 0:
		rec.Bytes = allBytes
	}
	return nil
}

func (p *nginxParser) assign(rec *Record, name, val string, uri, args *string, bodyBytes, allBytes *int64) error {
	var err error
	switch name {
	case "request":
		// "get /path?x=1 http/1.1". garbage like tls handshakes against a
		// plain port also lands here, so be strict.
		method, rest, ok := strings.Cut(val, " ")
		if !ok || method == "" || strings.ToUpper(method) != method {
			return errors.New("malformed request line")
		}
		target, _, _ := strings.Cut(rest, " ")
		if target == "" {
			return errors.New("malformed request line")
		}
		rec.Method = method
		*uri = target
	case "request_method":
		rec.Method = strings.ToUpper(val)
	case "request_uri":
		*uri = val
	case "uri":
		// $uri is the decoded, normalised path. only use it if nothing
		// better turned up.
		if *uri == "" {
			*uri = val
		}
	case "args", "query_string":
		*args = val
	case "status":
		rec.Status, err = strconv.Atoi(val)
	case "body_bytes_sent":
		*bodyBytes, err = strconv.ParseInt(val, 10, 64)
	case "bytes_sent":
		*allBytes, err = strconv.ParseInt(val, 10, 64)
	case "time_local":
		rec.Time, err = time.Parse("02/Jan/2006:15:04:05 -0700", val)
	case "time_iso8601":
		rec.Time, err = time.Parse(time.RFC3339, val)
	case "msec":
		rec.Time, err = parseUnixNumber(val)
	case "host", "http_host", "server_name":
		if rec.Host == "" || name == "host" {
			rec.Host = cleanHost(val)
		}
	case "scheme":
		rec.Scheme = strings.ToLower(val)
	case "upstream_cache_status":
		rec.CacheStatus = strings.ToLower(val)
	case "http_cookie":
		rec.Cookies = parseCookieHeader(val)
	default:
		switch {
		case strings.HasPrefix(name, "http_"):
			if rec.Header == nil {
				rec.Header = make(map[string]string, 4)
			}
			rec.Header[strings.ReplaceAll(name[5:], "_", "-")] = val
		case strings.HasPrefix(name, "cookie_"):
			if rec.Cookies == nil {
				rec.Cookies = make(map[string]string, 2)
			}
			rec.Cookies[name[7:]] = val
		}
	}
	return err
}

// undoes nginx's default log escaping, which writes '"', '\' and
// non-printable bytes as \xhh.
func unescapeNginx(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+3 < len(s) && s[i+1] == 'x' {
			if n, err := strconv.ParseUint(s[i+2:i+4], 16, 8); err == nil {
				b.WriteByte(byte(n))
				i += 3
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}
