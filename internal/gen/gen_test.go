package gen

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/shivashis-adhikari/keyfold/internal/plan"
)

func testPlan(mode string) *plan.Plan {
	trackers := []string{"fbclid", "gclid", "utm_campaign", "utm_medium", "utm_source"}
	return &plan.Plan{Version: 1, Mode: mode, Routes: []*plan.Route{
		{Host: "shop.example.com", Pattern: "/products/{slug}", Cacheable: true,
			Query:  plan.Query{Keep: []string{"color", "size"}, Drop: trackers, Sort: true},
			Header: plan.Header{Lang: true}, Cookie: plan.Cookie{Include: []string{"currency"}},
			Flags: []plan.Flag{{Level: plan.High, Kind: "unkeyed-input", Name: "x-forwarded-host"}}},
		{Host: "shop.example.com", Pattern: "/", Cacheable: true, Query: plan.Query{Drop: trackers, Sort: true}, Header: plan.Header{Device: true}},
		{Host: "shop.example.com", Pattern: "/static/{asset}.js", Cacheable: true, Query: plan.Query{Keep: []string{"v"}, Sort: true}},
		{Host: "shop.example.com", Pattern: "/img/{name}.jpg", Cacheable: true, Query: plan.Query{Keep: []string{"q", "w"}, Drop: []string{"utm_source"}, Sort: true}, Header: plan.Header{Include: []string{"accept"}}},
		{Host: "shop.example.com", Pattern: "/search", Cacheable: true, Query: plan.Query{Keep: []string{"page", "q", "sort"}, Unverified: []string{"ref"}}},
		{Host: "shop.example.com", Pattern: "/blog/{slug}", Cacheable: true, Query: plan.Query{Drop: trackers, Sort: true}},
		{Host: "shop.example.com", Pattern: "/account", Cacheable: false},
	}}
}

func TestCloudflareEnterprise(t *testing.T) {
	out, warns, err := Cloudflare(testPlan(plan.Safe), Options{})
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]struct {
		Rules []cfRule `json:"rules"`
	}
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatalf("not json: %v\n%s", err, out)
	}
	rules := doc["http_request_cache_settings"].Rules
	// /search keeps everything in the original order: no rule. /account
	// isn't cacheable: no rule.
	if len(rules) != 5 {
		t.Fatalf("want 5 rules, got %d: %s", len(rules), out)
	}
	// general first: two placeholder-ish patterns, then literal "/"
	if !strings.Contains(rules[len(rules)-1].Expression, `http.request.uri.path eq "/"`) {
		t.Errorf("literal route should come last, got %s", rules[len(rules)-1].Expression)
	}
	var prod *cfRule
	for i := range rules {
		if strings.Contains(rules[i].Description, "/products/{slug}") {
			prod = &rules[i]
		}
	}
	if prod == nil {
		t.Fatal("no product rule")
	}
	if want := `strict wildcard "/products/*" and not http.request.uri.path strict wildcard "/*/*/*"`; !strings.Contains(prod.Expression, want) {
		t.Errorf("expression %s", prod.Expression)
	}
	ck, _ := json.Marshal(prod.ActionParameters["cache_key"])
	for _, want := range []string{`"ignore_query_strings_order":true`, `"exclude":{"list":["fbclid","gclid","utm_campaign","utm_medium","utm_source"]}`, `"lang":true`, `"cookie":{"include":["currency"]}`} {
		if !strings.Contains(string(ck), want) {
			t.Errorf("cache key missing %s: %s", want, ck)
		}
	}
	if doc["http_request_late_transform"].Rules == nil {
		t.Error("x-forwarded-host reflection should produce a transform rule")
	}
	if len(warns) != 0 {
		t.Errorf("enterprise shouldn't warn: %v", warns)
	}
}

func TestCloudflareTiers(t *testing.T) {
	out, warns, err := Cloudflare(testPlan(plan.Tight), Options{CFPlan: "pro"})
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	if strings.Contains(s, "custom_key\": {\n              \"header") || strings.Contains(s, `"cookie"`) || strings.Contains(s, `"user"`) {
		t.Errorf("pro plan output uses enterprise-only parts:\n%s", s)
	}
	// /blog keeps nothing in tight mode, so ignoring the query is allowed
	if !strings.Contains(s, `"all": true`) {
		t.Errorf("expected ignore-all for /blog:\n%s", s)
	}
	if len(warns) == 0 {
		t.Error("expected warnings about enterprise-only parts")
	}
	if _, _, err := Cloudflare(testPlan(plan.Safe), Options{CFPlan: "pro", CFRegex: true}); err == nil {
		t.Error("regex on pro should be refused")
	}
	if _, _, err := Cloudflare(testPlan(plan.Safe), Options{CFPlan: "gold"}); err == nil {
		t.Error("unknown tier should be refused")
	}
}

func TestCloudflareCanary(t *testing.T) {
	out, _, _ := Cloudflare(testPlan(plan.Safe), Options{Canary: true})
	s := string(out)
	if strings.Count(s, `any(http.request.headers[\"x-keyfold-canary\"][*] eq \"1\")`) != 5 {
		t.Errorf("every cache rule should be gated on the canary header:\n%s", s)
	}
	if !strings.Contains(s, `"x-keyfold-canary"`) {
		t.Error("canary header should be in the key")
	}
}

func TestCaddyContent(t *testing.T) {
	out, _, _ := Caddy(testPlan(plan.Safe), Options{})
	s := string(out)
	for _, want := range []string{
		"uri @kf", "-utm_source", "sort_query", "request_header -X-Keyfold-*", "request_header -X-Forwarded-Host",
		`X-Keyfold-C-Currency "{http.request.cookie.currency}"`, "headers X-Keyfold-Lang X-Keyfold-C-Currency",
		`^/products/[^/?]+([?]|$) {`,
	} {
		if !strings.Contains(s, want) {
			t.Errorf("caddyfile missing %q:\n%s", want, s)
		}
	}
	out, _, _ = Caddy(testPlan(plan.Tight), Options{Canary: true})
	s = string(out)
	if strings.Contains(s, "uri @kf") {
		t.Error("tight mode shouldn't rewrite the request")
	}
	if !strings.Contains(s, "color={http.request.uri.query.color}&size={http.request.uri.query.size}") || !strings.Contains(s, "header X-Keyfold-Canary 1") {
		t.Errorf("tight template/canary missing:\n%s", s)
	}
}

func TestNginxContent(t *testing.T) {
	out, warns, _ := Nginx(testPlan(plan.Safe), Options{})
	s := string(out)
	for _, want := range []string{"map $uri $keyfold_route", "$keyfold_cache_key", "$cookie_currency", "$keyfold_lang", "utm_source"} {
		if !strings.Contains(s, want) {
			t.Errorf("nginx config missing %q:\n%s", want, s)
		}
	}
	if len(warns) == 0 {
		t.Error("nginx can't sort, expected a warning")
	}
	out, _, _ = Nginx(testPlan(plan.Tight), Options{Canary: true})
	if s := string(out); !strings.Contains(s, "q=$arg_q&w=$arg_w") || !strings.Contains(s, "$http_x_keyfold_canary:$uri") {
		t.Errorf("tight/canary nginx:\n%s", s)
	}
}

func binary(t *testing.T, env, name string, fallback ...string) string {
	t.Helper()
	if p := os.Getenv(env); p != "" {
		return p
	}
	if p, err := exec.LookPath(name); err == nil {
		return p
	}
	for _, f := range fallback {
		if _, err := os.Stat(f); err == nil {
			return f
		}
	}
	t.Skipf("%s not found, set %s to validate the generated config", name, env)
	return ""
}

// runs the generated caddyfile through caddy's own adapter. the caddy
// binary has to include the cache handler module.
func TestCaddyValidates(t *testing.T) {
	caddy := binary(t, "KEYFOLD_CADDY", "caddy")
	for _, mode := range []string{plan.Safe, plan.Tight} {
		for _, canary := range []bool{false, true} {
			snippet, _, _ := Caddy(testPlan(mode), Options{Canary: canary})
			dir := t.TempDir()
			cf := filepath.Join(dir, "Caddyfile")
			full := string(snippet) + "\n:0 {\n\timport keyfold_cache\n\trespond \"ok\"\n}\n"
			os.WriteFile(cf, []byte(full), 0o644)
			cmd := exec.Command(caddy, "validate", "--config", cf, "--adapter", "caddyfile")
			cmd.Env = append(os.Environ(), "HOME="+dir, "XDG_DATA_HOME="+dir, "XDG_CONFIG_HOME="+dir)
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Errorf("%s canary=%v: caddy validate failed: %v\n%s\n---\n%s", mode, canary, err, out, full)
			}
		}
	}
}

func TestNginxValidates(t *testing.T) {
	nginx := binary(t, "KEYFOLD_NGINX", "nginx", "/usr/sbin/nginx")
	for _, mode := range []string{plan.Safe, plan.Tight} {
		for _, canary := range []bool{false, true} {
			maps, _, _ := Nginx(testPlan(mode), Options{Canary: canary})
			dir := t.TempDir()
			os.WriteFile(filepath.Join(dir, "keyfold.conf"), maps, 0o644)
			conf := `pid ` + dir + `/nginx.pid;
error_log ` + dir + `/error.log;
events {}
http {
	access_log off;
	proxy_cache_path ` + dir + `/cache keys_zone=kf:1m;
	include ` + dir + `/keyfold.conf;
	server {
		listen 127.0.0.1:18080;
		location / {
			proxy_cache kf;
			proxy_cache_key $keyfold_cache_key;
			proxy_pass http://127.0.0.1:9;
		}
	}
}
`
			os.WriteFile(filepath.Join(dir, "nginx.conf"), []byte(conf), 0o644)
			cmd := exec.Command(nginx, "-t", "-q", "-p", dir, "-c", filepath.Join(dir, "nginx.conf"))
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Errorf("%s canary=%v: nginx -t failed: %v\n%s\n---\n%s", mode, canary, err, out, maps)
			}
		}
	}
}
