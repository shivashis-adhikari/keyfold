package canary

import (
	"context"
	"fmt"
	"io"
	"slices"
	"strings"

	"github.com/shivashis-adhikari/keyfold/internal/normalize"
)

const (
	Match    = "match"
	Mismatch = "mismatch"
	Drift    = "drift" // the origin changed too, not the key's fault
	Failed   = "error"
)

type Result struct {
	Route  string `json:"route"`
	Kind   string `json:"kind"`
	Why    string `json:"why,omitempty"`
	URI    string `json:"uri"`
	Status string `json:"status"`
	Detail string `json:"detail,omitempty"`
	Cache  string `json:"cache,omitempty"` // what the edge said: hit, miss, ...
}

type Report struct {
	Results    []Result `json:"results"`
	Matches    int      `json:"matches"`
	Mismatches int      `json:"mismatches"`
	Drifted    int      `json:"drifted"`
	Errors     int      `json:"errors"`
	// merge siblings the edge answered from cache. zero usually means the
	// new rules aren't live (or the canary header isn't reaching them).
	MergeHits int `json:"merge_hits"`
	Merges    int `json:"merges"`
}

// adds an optional origin to tell key mistakes from content
// that changed since the snapshot.
type VerifyOptions struct {
	Options
	Origin *Options
}

// replays a snapshot against the target, group by group, base first.
func Verify(ctx context.Context, snap *Snapshot, opts VerifyOptions) (*Report, error) {
	if err := opts.defaults(); err != nil {
		return nil, err
	}
	if snap.Canary {
		opts.Canary = true
	}
	edge := newFetcher(opts.Options)
	defer edge.tick.Stop()
	var origin *fetcher
	if opts.Origin != nil {
		if err := opts.Origin.defaults(); err != nil {
			return nil, err
		}
		origin = newFetcher(*opts.Origin)
		defer origin.tick.Stop()
	}

	rep := &Report{}
	for _, g := range snap.Groups {
		for _, e := range g.Entries {
			if e.Error != "" {
				continue // nothing to compare against
			}
			res := Result{Route: g.Route, Kind: e.Kind, Why: e.Why, URI: e.URI}
			got, err := edge.get(ctx, e)
			if err != nil {
				res.Status, res.Detail = Failed, err.Error()
				rep.add(res)
				continue
			}
			res.Cache = got.cache
			if e.Kind == Merge {
				rep.Merges++
				if got.cache == "hit" {
					rep.MergeHits++
				}
			}
			if d := compare(e, got); d == "" {
				res.Status = Match
			} else {
				res.Status, res.Detail = Mismatch, d
				if origin != nil {
					if now, err := origin.get(ctx, e); err == nil && compare(e, now) != "" {
						res.Status, res.Detail = Drift, "origin no longer matches the snapshot either: "+d
					}
				}
			}
			rep.add(res)
		}
		if ctx.Err() != nil {
			return rep, ctx.Err()
		}
	}
	return rep, nil
}

func (r *Report) add(res Result) {
	r.Results = append(r.Results, res)
	switch res.Status {
	case Match:
		r.Matches++
	case Mismatch:
		r.Mismatches++
	case Drift:
		r.Drifted++
	default:
		r.Errors++
	}
}

func compare(e Entry, got response) string {
	if !got.fp.SameMeta(e.FP) {
		return got.fp.Diff(e.FP)
	}
	if e.Stable {
		if got.fp.Body != e.FP.Body {
			return "body hash " + got.fp.Body + ", recorded " + e.FP.Body
		}
		return ""
	}
	var v normalize.Volatile
	v.Add(e.Tokens)
	v.Mark(e.Noise)
	var left []string
	for _, tok := range v.Residual(got.tokens, 0) {
		if sh := normalize.Shape(tok); sh == "" || !slices.Contains(e.Shapes, sh) {
			left = append(left, tok)
		}
	}
	if len(left) > 0 {
		if len(left) > 6 {
			left = left[:6]
		}
		return "body differs: " + strings.Join(left, " ")
	}
	return ""
}

func (r *Report) Print(w io.Writer) {
	for _, res := range r.Results {
		if res.Status == Match {
			continue
		}
		fmt.Fprintf(w, "%-8s %-5s %-32s %s\n         %s (%s)\n", res.Status, res.Kind, trim(res.Route, 32), res.URI, res.Detail, res.Why)
	}
	fmt.Fprintf(w, "%d match, %d mismatch, %d drifted, %d errors\n", r.Matches, r.Mismatches, r.Drifted, r.Errors)
	if r.Merges > 0 {
		fmt.Fprintf(w, "%d of %d urls that should share a cache entry were served from cache\n", r.MergeHits, r.Merges)
		if r.MergeHits == 0 {
			fmt.Fprintln(w, "none were cache hits: the new rules may not be live, or the edge doesn't report cache status")
		}
	}
}

func trim(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-3] + "..."
}
