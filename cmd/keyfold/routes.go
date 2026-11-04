package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"

	"github.com/shivashis-adhikari/keyfold/internal/logs"
	"github.com/shivashis-adhikari/keyfold/internal/routes"
)

type logFlags struct {
	format, nginxFormat, host, scheme string
	collapse                          int
}

func (l *logFlags) register(fs *flag.FlagSet) {
	fs.StringVar(&l.format, "format", "auto", "log format: auto, cloudflare, caddy or nginx")
	fs.StringVar(&l.nginxFormat, "nginx-format", "", "nginx log_format string, if not the default combined format")
	fs.StringVar(&l.host, "host", "", "host for log lines that don't carry one (nginx combined doesn't)")
	fs.StringVar(&l.scheme, "scheme", "https", "scheme for log lines that don't carry one")
	fs.IntVar(&l.collapse, "collapse", 20, "distinct literal path segments at one position before they fold into {slug}")
}

func (l *logFlags) open(paths []string) (*logs.Scanner, error) {
	f, err := logs.ParseFormat(l.format)
	if err != nil {
		return nil, err
	}
	return logs.Open(paths, logs.Options{Format: f, NginxFormat: l.nginxFormat, DefaultHost: l.host, DefaultScheme: l.scheme}), nil
}

// one pass over the logs into a route inventory
func (l *logFlags) inventory(paths []string, stderr io.Writer) (*routes.Inventory, error) {
	sc, err := l.open(paths)
	if err != nil {
		return nil, err
	}
	defer sc.Close()
	b := routes.NewBuilder(routes.Options{CollapseAt: l.collapse})
	for sc.Scan() {
		b.Add(sc.Record())
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	reportSkipped(stderr, sc)
	if sc.Lines == 0 {
		return nil, fmt.Errorf("no log lines read")
	}
	if sc.Lines == sc.Skipped {
		return nil, fmt.Errorf("none of the %d lines parsed, wrong -format?", sc.Lines)
	}
	return b.Finish(), nil
}

func reportSkipped(w io.Writer, sc *logs.Scanner) {
	if sc.Skipped == 0 {
		return
	}
	fmt.Fprintf(w, "skipped %d of %d lines\n", sc.Skipped, sc.Lines)
	for _, e := range sc.Errors {
		fmt.Fprintf(w, "  %s\n", e)
	}
}

func cmdRoutes(args []string, stdout, stderr io.Writer) error {
	fs := newFlags("routes", "logs...", stderr)
	var lf logFlags
	lf.register(fs)
	top := fs.Int("top", 25, "routes to show")
	asJSON := fs.Bool("json", false, "print the full inventory as json")
	if err := fs.Parse(args); err != nil {
		return err
	}
	inv, err := lf.inventory(fs.Args(), stderr)
	if err != nil {
		return err
	}
	if *asJSON {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(inv)
	}
	fmt.Fprintf(stdout, "%d requests, %d routes, %s to %s\n\n", inv.Requests, len(inv.Routes),
		inv.Start.Format("2006-01-02 15:04"), inv.End.Format("2006-01-02 15:04"))
	tw := tabwriter.NewWriter(stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "route\trequests\tcdn hit\turls\tpaths\turls/path\tparams (distinct values)")
	for i, r := range inv.Routes {
		if i >= *top {
			break
		}
		var ps []string
		for j, p := range r.Params {
			if j >= 5 {
				ps = append(ps, fmt.Sprintf("+%d more", len(r.Params)-5))
				break
			}
			ps = append(ps, fmt.Sprintf("%s (%d)", p.Name, p.Distinct))
		}
		name := r.Pattern
		if r.Host != "" && len(hosts(inv)) > 1 {
			name = r.Host + r.Pattern
		}
		hit := "-"
		if r.CDNStatuses > 0 {
			hit = fmt.Sprintf("%.0f%%", 100*float64(r.CDNHits)/float64(r.CDNStatuses))
		}
		fmt.Fprintf(tw, "%s\t%d\t%s\t%d\t%d\t%.1f\t%s\n", name, r.Requests, hit,
			r.UniqueURLs, r.UniquePaths, r.Fragmentation(), strings.Join(ps, ", "))
	}
	tw.Flush()
	if len(inv.Routes) > *top {
		fmt.Fprintf(stdout, "... %d more routes, -top to see them\n", len(inv.Routes)-*top)
	}
	return nil
}

func hosts(inv *routes.Inventory) map[string]bool {
	out := map[string]bool{}
	for _, r := range inv.Routes {
		out[r.Host] = true
	}
	return out
}
