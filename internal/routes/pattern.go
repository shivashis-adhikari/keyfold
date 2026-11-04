// package routes groups request paths into route patterns like
// /products/{slug} and keeps per-route stats on query params and cookies.
package routes

import (
	"strings"
)

// placeholders a pattern segment can hold. "{name}.ext", "{asset}.ext" and
// "{int}.ext" keep the file extension, so /img/{name}.png and
// /img/{name}.svg stay apart.
const (
	phInt   = "{int}"
	phUUID  = "{uuid}"
	phHex   = "{hex}"
	phDate  = "{date}"
	phToken = "{token}"
	phSlug  = "{slug}"
	phName  = "{name}"
	phAsset = "{asset}"
)

// 8-4-4-4-12 hex. checked by hand, this runs for every path segment of
// every log line and a regex was a tenth of the inventory's cpu time.
func isUUID(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i := 0; i < 36; i++ {
		switch i {
		case 8, 13, 18, 23:
			if s[i] != '-' {
				return false
			}
		default:
			if !isHex(s[i : i+1]) {
				return false
			}
		}
	}
	return true
}

// yyyy-mm-dd
func isDate(s string) bool {
	return len(s) == 10 && s[4] == '-' && s[7] == '-' && allDigits(s[:4]) && allDigits(s[5:7]) && allDigits(s[8:])
}

// maps one raw path segment to itself or to a placeholder. this is the cheap
// first pass. high-cardinality literal segments (product slugs and the like)
// get folded later, once we've seen all of them.
func classify(seg string) string {
	switch {
	case seg == "":
		return ""
	case allDigits(seg):
		return phInt
	case isUUID(seg):
		return phUUID
	case isDate(seg):
		return phDate
	case len(seg) >= 12 && isHex(seg) && hasDigit(seg) && hasLetter(seg):
		return phHex
	}
	if name, ext, ok := splitExt(seg); ok {
		switch {
		case allDigits(name):
			return phInt + ext
		case isFingerprinted(name):
			return phAsset + ext
		}
		return seg
	}
	if isToken(seg) {
		return phToken
	}
	return seg
}

func isPlaceholder(seg string) bool { return strings.HasPrefix(seg, "{") }

func splitExt(seg string) (name, ext string, ok bool) {
	i := strings.LastIndexByte(seg, '.')
	if i <= 0 || len(seg)-i-1 < 1 || len(seg)-i-1 > 6 {
		return "", "", false
	}
	for _, c := range seg[i+1:] {
		if !isAlnum(byte(c)) {
			return "", "", false
		}
	}
	return seg[:i], seg[i:], true
}

// app.3f9c2a1b, vite's mixed-case base64 chunks, vendor_9f8e7d6c5b and so on. bundlers put a
// hash chunk in the name so the file can be cached forever.
func isFingerprinted(name string) bool {
	for _, chunk := range strings.FieldsFunc(name, func(r rune) bool { return r == '.' || r == '-' || r == '_' }) {
		if len(chunk) >= 8 && isHex(chunk) && hasDigit(chunk) {
			return true
		}
		if len(chunk) >= 8 && len(chunk) <= 12 && hasDigit(chunk) && hasUpper(chunk) && hasLower(chunk) {
			return true
		}
	}
	return false
}

// long opaque ids: base62 tokens, sha-ish strings with dashes and so on.
// readable slugs are lowercase words with a few digits, those stay literal.
func isToken(seg string) bool {
	if len(seg) < 20 {
		return false
	}
	digits := 0
	for i := 0; i < len(seg); i++ {
		c := seg[i]
		if !isAlnum(c) && c != '-' && c != '_' {
			return false
		}
		if c >= '0' && c <= '9' {
			digits++
		}
	}
	if digits == 0 {
		return false
	}
	return hasUpper(seg) && hasLower(seg) || digits*4 >= len(seg)
}

func allDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

func isHex(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F') {
			return false
		}
	}
	return true
}

func isAlnum(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}

func hasDigit(s string) bool { return strings.ContainsAny(s, "0123456789") }
func hasUpper(s string) bool {
	return strings.IndexFunc(s, func(r rune) bool { return r >= 'A' && r <= 'Z' }) >= 0
}
func hasLower(s string) bool {
	return strings.IndexFunc(s, func(r rune) bool { return r >= 'a' && r <= 'z' }) >= 0
}
func hasLetter(s string) bool { return hasUpper(s) || hasLower(s) }

// splits "/a/b/" into ["a", "b", ""]. the root path is [""].
func splitPath(p string) []string {
	p = strings.TrimPrefix(p, "/")
	return strings.Split(p, "/")
}

func joinPath(segs []string) string { return "/" + strings.Join(segs, "/") }

// reports whether a concrete path segment fits a pattern segment.
func segMatches(pat, seg string) bool {
	if !isPlaceholder(pat) {
		return pat == seg
	}
	if seg == "" {
		return false
	}
	base, ext := pat, ""
	if i := strings.IndexByte(pat, '}'); i >= 0 && i+1 < len(pat) {
		base, ext = pat[:i+1], pat[i+1:]
	}
	if ext != "" {
		if !strings.HasSuffix(seg, ext) || len(seg) == len(ext) {
			return false
		}
		seg = seg[:len(seg)-len(ext)]
	}
	switch base {
	case phInt:
		return allDigits(seg)
	case phUUID:
		return isUUID(seg)
	case phDate:
		return isDate(seg)
	case phHex:
		return isHex(seg)
	case phToken:
		return isToken(seg)
	case phAsset:
		return isFingerprinted(seg)
	}
	return true // {slug}, {name}
}

// returns an anchored regular expression for a pattern. it avoids
// counted repetition like {8} on purpose: braces would clash with caddyfile
// placeholders.
func Regex(pattern string) string {
	var b strings.Builder
	b.WriteString("^")
	for _, seg := range splitPath(pattern) {
		b.WriteString("/")
		b.WriteString(segRegex(seg))
	}
	b.WriteString("$")
	return b.String()
}

// like the stdlib's regex quoting, but with character classes instead of backslashes
// where it can. the output ends up inside caddyfiles, nginx strings and json,
// each with its own idea of what a backslash means; caddy's cache handler
// even fails to re-encode one.
func quoteMeta(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch c {
		case '.', '+', '*', '?', '(', ')', '|', '[', '{', '}', '$':
			b.WriteByte('[')
			b.WriteByte(c)
			b.WriteByte(']')
		case '\\', '^', ']':
			b.WriteByte('\\')
			b.WriteByte(c)
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}

func segRegex(seg string) string {
	if !isPlaceholder(seg) {
		return quoteMeta(seg)
	}
	base, ext := seg, ""
	if i := strings.IndexByte(seg, '}'); i >= 0 {
		base, ext = seg[:i+1], seg[i+1:]
	}
	var r string
	switch base {
	case phInt:
		r = `[0-9]+`
	case phUUID, phHex:
		r = `[0-9a-fA-F-]+`
	case phDate:
		r = `[0-9]+-[0-9]+-[0-9]+`
	case phToken:
		r = `[A-Za-z0-9_-]+`
	default:
		r = `[^/]+`
	}
	if ext != "" {
		// a {slug}-style prefix must not eat the extension's dot
		if r == `[^/]+` {
			r = `[^/]+?`
		}
		r += quoteMeta(ext)
	}
	return r
}

// returns the pattern with every placeholder segment turned into
// '*'. a '*' in cloudflare's wildcard operator also matches '/', so callers
// need to pin the segment count separately.
func Wildcard(pattern string) string {
	segs := splitPath(pattern)
	for i, s := range segs {
		if !isPlaceholder(s) {
			continue
		}
		if j := strings.IndexByte(s, '}'); j >= 0 && j+1 < len(s) {
			segs[i] = "*" + s[j+1:]
		} else {
			segs[i] = "*"
		}
	}
	return joinPath(segs)
}

// the number of '/' in paths the pattern can match.
func SegmentCount(pattern string) int { return len(splitPath(pattern)) }

// reports whether the pattern matches more than one path.
func HasPlaceholder(pattern string) bool { return strings.Contains(pattern, "{") }

// regex-escapes s the same way patterns are escaped.
func QuoteMeta(s string) string { return quoteMeta(s) }
