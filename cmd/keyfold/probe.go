package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/shivashis-adhikari/keyfold/internal/normalize"
	"github.com/shivashis-adhikari/keyfold/internal/probe"
)

func cmdProbe(args []string, stdout, stderr io.Writer) error {
	fs := newFlags("probe", "-origin url logs...", stderr)
	var lf logFlags
	lf.registerRoutes(fs)
	origin := fs.String("origin", "", "origin to probe, e.g. http://10.0.3.7:8080. not the cdn")
	hostHeader := fs.String("host-header", "", "host header to send (default: the host from the logs)")
	nRoutes := fs.Int("routes", 25, "busiest cacheable routes to probe")
	samples := fs.Int("samples", 4, "sample urls per route")
	baselines := fs.Int("baselines", 3, "baseline fetches per url")
	rate := fs.Float64("rate", 10, "requests per second, total")
	conc := fs.Int("concurrency", 4, "urls probed at once")
	timeout := fs.Duration("timeout", 15*time.Second, "per request timeout")
	buster := fs.String("cache-buster", "", "add this param with a random value to every request, if the origin has its own cache in front")
	skipHeaders := fs.Bool("skip-headers", false, "don't probe accept-language, user-agent and friends")
	insecure := fs.Bool("insecure", false, "don't verify the origin's tls certificate")
	out := fs.String("o", "probe.json", "where to write the report")
	var headers, cookies, ignore multi
	fs.Var(&headers, "header", "header to send on every request, 'name: value' (repeatable)")
	fs.Var(&cookies, "cookie", "cookie to send on every request, name=value (repeatable)")
	fs.Var(&ignore, "ignore", "regex for response content to ignore when comparing (repeatable)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *origin == "" {
		fs.Usage()
		return fmt.Errorf("-origin is required")
	}
	u, err := url.Parse(*origin)
	if err != nil {
		return fmt.Errorf("-origin: %w", err)
	}
	norm, err := normalize.New(ignore)
	if err != nil {
		return err
	}
	h := http.Header{}
	for _, kv := range headers {
		k, v, ok := strings.Cut(kv, ":")
		if !ok {
			return fmt.Errorf("-header %q: want 'name: value'", kv)
		}
		h.Add(strings.TrimSpace(k), strings.TrimSpace(v))
	}
	ck := map[string]string{}
	for _, kv := range cookies {
		k, v, ok := strings.Cut(kv, "=")
		if !ok {
			return fmt.Errorf("-cookie %q: want name=value", kv)
		}
		ck[k] = v
	}

	inv, err := lf.inventory(fs.Args(), stderr)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	rep, err := probe.Run(ctx, inv, probe.Options{
		Origin: u, HostHeader: *hostHeader, Routes: *nRoutes, Samples: *samples, Baselines: *baselines,
		Rate: *rate, Concurrency: *conc, Timeout: *timeout, Insecure: *insecure,
		Header: h, Cookies: ck, CacheBuster: *buster, SkipHeaders: *skipHeaders,
		Normalizer: norm, Progress: stderr,
	})
	if rep != nil {
		if werr := writeJSON(*out, rep); werr != nil {
			return werr
		}
		fmt.Fprintf(stdout, "%d requests in %s, report in %s\n", rep.Requests, rep.Finished.Sub(rep.Started).Round(time.Second), *out)
	}
	return err
}

func writeJSON(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	if path == "-" {
		_, err = os.Stdout.Write(append(b, '\n'))
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o644)
}

func readJSON(path string, v any) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(b, v); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	return nil
}
