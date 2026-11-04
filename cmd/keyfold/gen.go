package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/signal"

	"github.com/shivashis-adhikari/keyfold/internal/canary"
	"github.com/shivashis-adhikari/keyfold/internal/gen"
	"github.com/shivashis-adhikari/keyfold/internal/plan"
)

func cmdGen(args []string, stdout, stderr io.Writer) error {
	fs := newFlags("gen", "-plan plan.json -target cloudflare|caddy|nginx", stderr)
	planPath := fs.String("plan", "plan.json", "plan from keyfold synth")
	target := fs.String("target", "", "cloudflare, caddy or nginx")
	cfPlan := fs.String("cf-plan", "enterprise", "cloudflare plan tier: free, pro, business or enterprise")
	cfRegex := fs.Bool("cf-regex", false, "cloudflare: match paths with regex (business and up) instead of wildcards")
	canaryMode := fs.Bool("canary", false, "only apply the new key to requests with "+gen.CanaryHeader+": 1")
	out := fs.String("o", "-", "output file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	p, err := plan.Load(*planPath)
	if err != nil {
		return err
	}
	opts := gen.Options{Canary: *canaryMode, CFPlan: *cfPlan, CFRegex: *cfRegex}
	var b []byte
	var warns []string
	switch *target {
	case "cloudflare", "cf":
		b, warns, err = gen.Cloudflare(p, opts)
	case "caddy":
		b, warns, err = gen.Caddy(p, opts)
	case "nginx":
		b, warns, err = gen.Nginx(p, opts)
	default:
		fs.Usage()
		return fmt.Errorf("-target %q, want cloudflare, caddy or nginx", *target)
	}
	if err != nil {
		return err
	}
	for _, w := range warns {
		fmt.Fprintln(stderr, "warning:", w)
	}
	if *out == "-" {
		_, err = stdout.Write(b)
		return err
	}
	return os.WriteFile(*out, b, 0o644)
}

func cmdCanary(args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 || (args[0] != "record" && args[0] != "verify") {
		fmt.Fprint(stderr, "usage: keyfold canary record|verify [flags]\n\n"+
			"  record  fetch the plan's test urls and store response fingerprints\n"+
			"  verify  fetch them again through the edge and compare\n")
		return fmt.Errorf("want record or verify")
	}
	if args[0] == "record" {
		return canaryRecord(args[1:], stdout, stderr)
	}
	return canaryVerify(args[1:], stdout, stderr)
}

func canaryRecord(args []string, stdout, stderr io.Writer) error {
	fs := newFlags("canary record", "-plan plan.json -target url", stderr)
	planPath := fs.String("plan", "plan.json", "plan from keyfold synth")
	target := fs.String("target", "", "where to fetch from: the origin, or the edge before the change")
	hostHeader := fs.String("host-header", "", "host header to send (default: the plan's host)")
	samples := fs.Int("samples", 3, "base urls per route")
	siblings := fs.Int("siblings", 4, "urls per base that should share its cache entry")
	rate := fs.Float64("rate", 10, "requests per second")
	withCanary := fs.Bool("canary", false, "send "+gen.CanaryHeader+": 1, and remember to send it on verify too")
	out := fs.String("o", "snapshot.json", "where to write the snapshot")
	if err := fs.Parse(args); err != nil {
		return err
	}
	u, err := parseTarget(*target)
	if err != nil {
		return err
	}
	p, err := plan.Load(*planPath)
	if err != nil {
		return err
	}
	snap, err := canary.Record(ctxInterrupt(), p, canary.Options{Target: u, HostHeader: *hostHeader, Canary: *withCanary,
		Samples: *samples, Siblings: *siblings, Rate: *rate, Progress: stderr})
	if snap != nil {
		if werr := snap.Save(*out); werr != nil {
			return werr
		}
		n := 0
		for _, g := range snap.Groups {
			n += len(g.Entries)
		}
		fmt.Fprintf(stdout, "recorded %d urls across %d routes in %s\n", n, len(snap.Groups), *out)
	}
	return err
}

func canaryVerify(args []string, stdout, stderr io.Writer) error {
	fs := newFlags("canary verify", "-snapshot snapshot.json -target url", stderr)
	snapPath := fs.String("snapshot", "snapshot.json", "snapshot from keyfold canary record")
	target := fs.String("target", "", "the edge, after the change")
	origin := fs.String("origin", "", "optional: the origin, to tell content changes from key mistakes")
	hostHeader := fs.String("host-header", "", "host header to send (default: the plan's host)")
	rate := fs.Float64("rate", 10, "requests per second")
	maxMismatch := fs.Int("max-mismatch", 0, "mismatches tolerated before exiting non-zero")
	asJSON := fs.Bool("json", false, "print the report as json")
	if err := fs.Parse(args); err != nil {
		return err
	}
	u, err := parseTarget(*target)
	if err != nil {
		return err
	}
	snap, err := canary.Load(*snapPath)
	if err != nil {
		return err
	}
	vo := canary.VerifyOptions{Options: canary.Options{Target: u, HostHeader: *hostHeader, Rate: *rate}}
	if *origin != "" {
		ou, err := parseTarget(*origin)
		if err != nil {
			return err
		}
		vo.Origin = &canary.Options{Target: ou, HostHeader: *hostHeader, Rate: *rate, Canary: snap.Canary}
	}
	rep, err := canary.Verify(ctxInterrupt(), snap, vo)
	if err != nil {
		return err
	}
	if *asJSON {
		if err := writeJSONTo(stdout, rep); err != nil {
			return err
		}
	} else {
		rep.Print(stdout)
	}
	if rep.Mismatches > *maxMismatch {
		return exitCode(1)
	}
	return nil
}

func parseTarget(s string) (*url.URL, error) {
	if s == "" {
		return nil, fmt.Errorf("-target is required")
	}
	u, err := url.Parse(s)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, fmt.Errorf("%q isn't an http(s) url", s)
	}
	return u, nil
}

// cancelled on ctrl-c, so a long record or verify still writes what it has
func ctxInterrupt() context.Context {
	ctx, _ := signal.NotifyContext(context.Background(), os.Interrupt)
	return ctx
}

func writeJSONTo(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}
