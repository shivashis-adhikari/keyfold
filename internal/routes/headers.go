package routes

import "strings"

// the primary language subtag of an accept-language header, lowercased.
// this is what cloudflare's "lang" cache key option keys on.
func FirstLanguage(h string) string {
	h = strings.TrimSpace(h)
	if h == "" {
		return ""
	}
	first, _, _ := strings.Cut(h, ",")
	first, _, _ = strings.Cut(first, ";")
	first, _, _ = strings.Cut(strings.TrimSpace(first), "-")
	return strings.ToLower(strings.TrimSpace(first))
}

// buckets a user agent into mobile, tablet or desktop, roughly the way cdn
// device-type keys do. it doesn't need to be clever, just consistent.
func DeviceType(ua string) string {
	u := strings.ToLower(ua)
	switch {
	case strings.Contains(u, "ipad"), strings.Contains(u, "tablet"),
		strings.Contains(u, "android") && !strings.Contains(u, "mobile"):
		return "tablet"
	case strings.Contains(u, "mobi"), strings.Contains(u, "iphone"), strings.Contains(u, "ipod"),
		strings.Contains(u, "android"), strings.Contains(u, "blackberry"), strings.Contains(u, "opera mini"):
		return "mobile"
	}
	return "desktop"
}
