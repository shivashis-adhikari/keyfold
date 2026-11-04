package main

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/shivashis-adhikari/keyfold/internal/plan"
	"github.com/shivashis-adhikari/keyfold/internal/sim"
)

func cmdSim(args []string, stdout, stderr io.Writer) error {
	fs := newFlags("sim", "-plan plan.json logs...", stderr)
	var lf logFlags
	lf.register(fs)
	planPath := fs.String("plan", "plan.json", "plan from keyfold synth")
	policies := fs.String("policies", "lru,fifo,sieve,s3fifo,tinylfu", "eviction policies to replay")
	sizes := fs.String("sizes", "0.5%,2%,10%,50%", "cache sizes, as a share of today's working set or absolute (512MB, 4GiB)")
	ttl := fs.Duration("ttl", time.Hour, "ttl for routes without a max-age and for requests outside the plan")
	egress := fs.Float64("egress", 0.09, "origin egress price, $ per gb")
	perMillion := fs.Float64("per-million", 0, "origin compute price, $ per million requests")
	detail := fs.String("detail", "s3fifo@10%", "policy@size to break down per route, empty to skip")
	asJSON := fs.Bool("json", false, "print results as json")
	if err := fs.Parse(args); err != nil {
		return err
	}
	p, err := plan.Load(*planPath)
	if err != nil {
		return err
	}
	sz, err := sim.ParseSizes(*sizes)
	if err != nil {
		return err
	}
	sc, err := lf.open(fs.Args())
	if err != nil {
		return err
	}
	defer sc.Close()
	start := time.Now()
	tr, err := sim.Build(sc, p, sim.BuildOptions{DefaultTTL: *ttl})
	if err != nil {
		return err
	}
	reportSkipped(stderr, sc)
	if tr.Len() == 0 {
		return fmt.Errorf("nothing to replay: no cacheable get requests in the logs")
	}
	res, err := sim.Run(tr, sim.Config{Policies: strings.Split(*policies, ","), Sizes: sz})
	if err != nil {
		return err
	}
	costs := sim.Costs{EgressPerGB: *egress, PerMillion: *perMillion}

	var routes []sim.RouteResult
	var detailPolicy, detailSize string
	if *detail != "" {
		pol, size, ok := strings.Cut(*detail, "@")
		ds, err := sim.ParseSizes(size)
		if !ok || err != nil {
			return fmt.Errorf("-detail %q, want policy@size like s3fifo@10%%", *detail)
		}
		routes = sim.ByRoute(tr, pol, ds[0])
		detailPolicy, detailSize = pol, size
	}

	if *asJSON {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(map[string]any{
			"requests": tr.Len(), "span_seconds": tr.Span().Seconds(),
			"keys":    map[string]int{"current": tr.CurKeys, "planned": tr.PropKeys},
			"results": res, "routes": routes,
		})
	}

	tr.Summary(stdout)
	if missing := tr.Unsimulated(p); len(missing) > 0 {
		fmt.Fprintf(stdout, "note: the plan keys on %s, which the logs don't record. the replay treats them as\n"+
			"      constant, so the planned numbers for those routes are optimistic.\n", strings.Join(missing, ", "))
	}
	fmt.Fprintln(stdout)
	tw := tabwriter.NewWriter(stdout, 0, 0, 2, ' ', tabwriter.AlignRight)
	fmt.Fprintln(tw, "policy\tsize\tcapacity\thit ratio\t\tbyte hit ratio\t\torigin requests\t\torigin traffic\t\tsaved / 30d\t")
	fmt.Fprintln(tw, "\t\t\tnow\tplanned\tnow\tplanned\tnow\tplanned\tnow\tplanned\t\t")
	for _, r := range res {
		capacity := sim.HumanBytes(r.Capacity)
		if r.Policy == "inf" {
			capacity = "unbounded"
		}
		saved := costs.Monthly(r.Current, tr.Span()) - costs.Monthly(r.Proposed, tr.Span())
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%d\t%d\t%s\t%s\t$%.2f\t\n", r.Policy, r.Size, capacity,
			pct(r.Current.HitRatio()), pct(r.Proposed.HitRatio()), pct(r.Current.ByteHitRatio()), pct(r.Proposed.ByteHitRatio()),
			r.Current.OriginRequests(), r.Proposed.OriginRequests(),
			sim.HumanBytes(r.Current.OriginBytes()), sim.HumanBytes(r.Proposed.OriginBytes()), saved)
	}
	tw.Flush()
	fmt.Fprintf(stdout, "\n'saved' projects the origin cost difference over 30 days at $%.3f/gb egress", *egress)
	if *perMillion > 0 {
		fmt.Fprintf(stdout, " and $%.2f per million requests", *perMillion)
	}
	fmt.Fprintln(stdout, ".")

	if len(routes) > 0 {
		sort.Slice(routes, func(i, j int) bool {
			return routes[i].Current.OriginBytes()-routes[i].Proposed.OriginBytes() > routes[j].Current.OriginBytes()-routes[j].Proposed.OriginBytes()
		})
		fmt.Fprintf(stdout, "\nper route, %s at %s:\n", detailPolicy, detailSize)
		tw = tabwriter.NewWriter(stdout, 0, 0, 2, ' ', tabwriter.AlignRight)
		fmt.Fprintln(tw, "route\trequests\thit now\tplanned\torigin traffic saved\t")
		for _, r := range routes {
			fmt.Fprintf(tw, "%s\t%d\t%s\t%s\t%s\t\n", r.Route, r.Current.Requests, pct(r.Current.HitRatio()), pct(r.Proposed.HitRatio()),
				sim.HumanBytes(r.Current.OriginBytes()-r.Proposed.OriginBytes()))
		}
		tw.Flush()
	}
	fmt.Fprintf(stderr, "replayed %d requests x %d configurations in %s\n", tr.Len(), 2*len(res), time.Since(start).Round(time.Millisecond))
	return nil
}

func pct(f float64) string { return fmt.Sprintf("%.1f%%", 100*f) }
