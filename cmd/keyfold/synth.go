package main

import (
	"fmt"
	"io"
	"strings"
	"text/tabwriter"

	"github.com/shivashis-adhikari/keyfold/internal/plan"
	"github.com/shivashis-adhikari/keyfold/internal/probe"
	"github.com/shivashis-adhikari/keyfold/internal/synth"
)

func cmdSynth(args []string, stdout, stderr io.Writer) error {
	fs := newFlags("synth", "probe.json", stderr)
	mode := fs.String("mode", plan.Safe, "safe: drop only params proven to be noise. tight: keep only params proven (or not disproven) to matter")
	minEv := fs.Int("min-evidence", 2, "noise verdicts needed before a param is dropped")
	trust := fs.Bool("trust-trackers", false, "drop known tracking params (utm_*, gclid, fbclid, ...) even when no probe covered them")
	out := fs.String("o", "plan.json", "where to write the plan")
	quiet := fs.Bool("q", false, "don't print the plan summary")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		fs.Usage()
		return fmt.Errorf("want one probe report")
	}
	if *mode != plan.Safe && *mode != plan.Tight {
		return fmt.Errorf("-mode %q, want safe or tight", *mode)
	}
	var rep probe.Report
	if err := readJSON(fs.Arg(0), &rep); err != nil {
		return err
	}
	p := synth.Synthesize(&rep, synth.Options{Mode: *mode, MinEvidence: *minEv, TrustTrackers: *trust})
	if err := p.Save(*out); err != nil {
		return err
	}
	if !*quiet {
		printPlan(stdout, p)
	}
	fmt.Fprintf(stdout, "\nplan written to %s\n", *out)
	return nil
}

func printPlan(w io.Writer, p *plan.Plan) {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "route\tkeep\tdrop\tunverified\tsorted\talso keyed on")
	for _, r := range p.Routes {
		if !r.Cacheable {
			fmt.Fprintf(tw, "%s\t(not cacheable: %s)\t\t\t\t\n", r.Pattern, r.Uncacheable)
			continue
		}
		var also []string
		if r.Header.Lang {
			also = append(also, "language")
		}
		if r.Header.Device {
			also = append(also, "device")
		}
		for _, h := range r.Header.Include {
			also = append(also, "header "+h)
		}
		for _, c := range r.Cookie.Include {
			also = append(also, "cookie "+c)
		}
		for _, c := range r.Cookie.Presence {
			also = append(also, "cookie "+c+" (set or not)")
		}
		sorted := "no"
		if r.Query.Sort {
			sorted = "yes"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", r.Pattern, list(r.Query.Keep), list(r.Query.Drop), list(r.Query.Unverified), sorted, list(also))
	}
	tw.Flush()

	var flags []string
	for _, r := range p.Routes {
		for _, f := range r.Flags {
			if f.Level == plan.Info && f.Kind == "uncacheable" {
				continue
			}
			flags = append(flags, fmt.Sprintf("[%s] %s %s: %s", f.Level, r.Pattern, f.Kind, f.Detail))
		}
	}
	if len(flags) > 0 {
		fmt.Fprintln(w, "\nflags:")
		for _, f := range flags {
			fmt.Fprintln(w, "  "+f)
		}
	}
	for _, n := range p.Notes {
		fmt.Fprintln(w, "note: "+n)
	}
}

func list(xs []string) string {
	if len(xs) == 0 {
		return "-"
	}
	if len(xs) > 4 {
		return strings.Join(xs[:4], ",") + fmt.Sprintf(" +%d", len(xs)-4)
	}
	return strings.Join(xs, ",")
}
