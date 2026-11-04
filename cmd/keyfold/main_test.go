package main

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/shivashis-adhikari/keyfold/internal/fakeshop"
)

func keyfold(t *testing.T, args ...string) (string, string, int) {
	t.Helper()
	var out, errb bytes.Buffer
	code := run(args, &out, &errb)
	return out.String(), errb.String(), code
}

// every command, in the order the readme uses them, against the fake shop
func TestPipeline(t *testing.T) {
	if testing.Short() {
		t.Skip("probes the fake shop")
	}
	dir := t.TempDir()
	logPath := filepath.Join(dir, "access.log")
	var buf bytes.Buffer
	fakeshop.WriteTraffic(&buf, fakeshop.TrafficOptions{Requests: 40000, Format: "nginx"})
	os.WriteFile(logPath, buf.Bytes(), 0o644)
	srv := httptest.NewServer(fakeshop.New())
	defer srv.Close()
	at := func(name string) string { return filepath.Join(dir, name) }

	out, errs, code := keyfold(t, "routes", "-host", fakeshop.Host, logPath)
	if code != 0 || !strings.Contains(out, "/products/{slug}") {
		t.Fatalf("routes: %d\n%s\n%s", code, out, errs)
	}

	out, errs, code = keyfold(t, "probe", "-host", fakeshop.Host, "-origin", srv.URL, "-rate", "5000", "-concurrency", "8", "-o", at("probe.json"), logPath)
	if code != 0 {
		t.Fatalf("probe: %d\n%s\n%s", code, out, errs)
	}

	out, errs, code = keyfold(t, "synth", "-o", at("plan.json"), at("probe.json"))
	if code != 0 || !strings.Contains(out, "color,size") {
		t.Fatalf("synth: %d\n%s\n%s", code, out, errs)
	}

	out, errs, code = keyfold(t, "sim", "-host", fakeshop.Host, "-plan", at("plan.json"), "-sizes", "1%,10%", logPath)
	if code != 0 || !strings.Contains(out, "s3fifo") || !strings.Contains(out, "per route") {
		t.Fatalf("sim: %d\n%s\n%s", code, out, errs)
	}
	// nginx combined has user-agent but no accept-language, the sim has to
	// say so. (no cookies either, which is why this plan doesn't know about
	// the currency cookie at all: the probe only tries cookies it has seen
	// or was given with -cookie.)
	if !strings.Contains(out, "header accept-language") {
		t.Errorf("sim should warn that header key parts weren't simulated:\n%s", out)
	}
	out, _, code = keyfold(t, "sim", "-host", fakeshop.Host, "-plan", at("plan.json"), "-sizes", "5%", "-policies", "lru", "-json", logPath)
	var js map[string]any
	if code != 0 || json.Unmarshal([]byte(out), &js) != nil || js["results"] == nil {
		t.Fatalf("sim -json: %d %s", code, out)
	}

	for _, target := range []string{"cloudflare", "caddy", "nginx"} {
		if _, errs, code := keyfold(t, "gen", "-plan", at("plan.json"), "-target", target, "-o", at(target+".out")); code != 0 {
			t.Errorf("gen %s: %d %s", target, code, errs)
		}
	}

	_, errs, code = keyfold(t, "canary", "record", "-plan", at("plan.json"), "-target", srv.URL, "-host-header", fakeshop.Host, "-rate", "2000", "-o", at("snap.json"))
	if code != 0 {
		t.Fatalf("canary record: %d %s", code, errs)
	}
	// verifying against the origin itself must pass: it is the truth
	out, errs, code = keyfold(t, "canary", "verify", "-snapshot", at("snap.json"), "-target", srv.URL, "-host-header", fakeshop.Host, "-rate", "2000")
	if code != 0 || !strings.Contains(out, " 0 mismatch") {
		t.Fatalf("canary verify: %d\n%s\n%s", code, out, errs)
	}
}

func TestUsageAndErrors(t *testing.T) {
	if out, _, code := keyfold(t); code != 0 || !strings.Contains(out, "usage: keyfold") {
		t.Errorf("no args: %d %s", code, out)
	}
	if out, _, code := keyfold(t, "version"); code != 0 || !strings.HasPrefix(out, "keyfold ") {
		t.Errorf("version: %d %s", code, out)
	}
	if _, errs, code := keyfold(t, "frobnicate"); code != 2 || !strings.Contains(errs, "unknown command") {
		t.Errorf("unknown command: %d %s", code, errs)
	}
	if _, errs, code := keyfold(t, "probe", "x.log"); code != 1 || !strings.Contains(errs, "-origin is required") {
		t.Errorf("probe without origin: %d %s", code, errs)
	}
	if _, errs, code := keyfold(t, "gen", "-plan", "/nonexistent.json", "-target", "caddy"); code != 1 || !strings.Contains(errs, "no such file") {
		t.Errorf("gen with missing plan: %d %s", code, errs)
	}
	if _, _, code := keyfold(t, "routes", "-h"); code != 0 {
		t.Errorf("-h should exit 0, got %d", code)
	}
	empty := filepath.Join(t.TempDir(), "empty.log")
	os.WriteFile(empty, nil, 0o644)
	if _, errs, code := keyfold(t, "routes", empty); code != 1 || !strings.Contains(errs, "no log lines") {
		t.Errorf("empty log: %d %s", code, errs)
	}
}
