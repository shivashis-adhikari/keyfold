// package plan is the cache key proposal: per route, which query params,
// headers and cookies belong in the key. the synthesiser writes it, the
// simulator, config generators and canary read it.
package plan

import (
	"encoding/json"
	"fmt"
	"os"
	"slices"
	"time"
)

const (
	// safe mode drops only params the probe proved are noise. anything new
	// that shows up later stays in the key.
	Safe = "safe"
	// tight mode keeps only params proven (or not yet disproven) to matter.
	// smaller key, but a brand-new param that does change the page would be
	// ignored until the next probe.
	Tight = "tight"
)

type Plan struct {
	Version   int       `json:"version"`
	Generated time.Time `json:"generated"`
	Mode      string    `json:"mode"`
	Origin    string    `json:"origin,omitempty"`
	Routes    []*Route  `json:"routes"`
	Notes     []string  `json:"notes,omitempty"`
}

type Route struct {
	Host      string `json:"host"`
	Pattern   string `json:"pattern"`
	Requests  int64  `json:"requests"`
	Cacheable bool   `json:"cacheable"`
	// why not cacheable, from the origin's own headers
	Uncacheable string `json:"uncacheable,omitempty"`
	TTL         int64  `json:"ttl,omitempty"` // seconds, from cache-control

	Query  Query  `json:"query"`
	Header Header `json:"header"`
	Cookie Cookie `json:"cookie"`
	Flags  []Flag `json:"flags,omitempty"`

	// what made each kept part necessary, e.g. "color": "body differs: red blue"
	Evidence map[string]string `json:"evidence,omitempty"`
	// urls the prober used, and real values of the dropped params. the
	// canary builds its test requests from these.
	Samples []string            `json:"samples,omitempty"`
	Values  map[string][]string `json:"values,omitempty"`
}

type Query struct {
	Keep       []string `json:"keep"`       // proven to change the response
	Unverified []string `json:"unverified"` // seen in logs but never conclusively probed, kept
	Drop       []string `json:"drop"`       // proven noise
	Sort       bool     `json:"sort"`       // param order proven not to matter
}

type Header struct {
	Lang    bool     `json:"lang,omitempty"`    // primary language of accept-language
	Device  bool     `json:"device,omitempty"`  // mobile / tablet / desktop
	Include []string `json:"include,omitempty"` // raw header values, lowercase names
}

type Cookie struct {
	Include  []string `json:"include,omitempty"`  // value matters
	Presence []string `json:"presence,omitempty"` // only whether it is set matters
}

const (
	High = "high"
	Warn = "warn"
	Info = "info"
)

type Flag struct {
	Level  string `json:"level"`
	Kind   string `json:"kind"`
	Name   string `json:"name,omitempty"`
	Detail string `json:"detail"`
}

// whether the route's key differs from the default full-url key at all.
func (r *Route) Changed() bool {
	return len(r.Query.Drop) > 0 || r.Query.Sort || r.Header.Lang || r.Header.Device ||
		len(r.Header.Include) > 0 || len(r.Cookie.Include) > 0 || len(r.Cookie.Presence) > 0
}

// reports whether the key keeps a query param, under the plan's mode.
func (r *Route) KeepsParam(name string, mode string) bool {
	if mode == Tight {
		return slices.Contains(r.Query.Keep, name) || slices.Contains(r.Query.Unverified, name)
	}
	return !slices.Contains(r.Query.Drop, name)
}

func Load(path string) (*Plan, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var p Plan
	if err := json.Unmarshal(b, &p); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if p.Version != 1 {
		return nil, fmt.Errorf("%s: plan version %d, this build reads version 1", path, p.Version)
	}
	if p.Mode == "" {
		p.Mode = Safe
	}
	return &p, nil
}

func (p *Plan) Save(path string) error {
	b, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o644)
}
