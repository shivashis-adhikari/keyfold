package routes

import (
	"strings"
)

// maps a host and path to the most specific route pattern that fits.
// at each segment it tries, in order: the literal segment, its classified
// form ({int}, {asset}.js, ...), the {name}.ext fold, then {slug}. the first
// complete match wins, so /products/new beats /products/{slug}.
type Matcher struct {
	byHost  map[string]*mnode
	anyHost *mnode
}

type mnode struct {
	children map[string]*mnode
	id       int
}

func newMnode() *mnode { return &mnode{children: map[string]*mnode{}, id: -1} }

// builds a matcher. hosts[i] and patterns[i] describe route i; an
// empty host matches any host.
func NewMatcher(hosts, patterns []string) *Matcher {
	m := &Matcher{byHost: map[string]*mnode{}}
	for i, p := range patterns {
		var root *mnode
		if hosts[i] == "" {
			if m.anyHost == nil {
				m.anyHost = newMnode()
			}
			root = m.anyHost
		} else {
			root = m.byHost[hosts[i]]
			if root == nil {
				root = newMnode()
				m.byHost[hosts[i]] = root
			}
		}
		n := root
		for _, seg := range splitPath(p) {
			c := n.children[seg]
			if c == nil {
				c = newMnode()
				n.children[seg] = c
			}
			n = c
		}
		if n.id < 0 {
			n.id = i
		}
	}
	return m
}

// returns the route index for host+path, or -1.
func (m *Matcher) Match(host, path string) int {
	segs := splitPath(path)
	if root := m.byHost[host]; root != nil {
		if id := root.match(segs); id >= 0 {
			return id
		}
	}
	if m.anyHost != nil {
		return m.anyHost.match(segs)
	}
	return -1
}

func (n *mnode) match(segs []string) int {
	if len(segs) == 0 {
		return n.id
	}
	seg, rest := segs[0], segs[1:]
	try := func(key string) int {
		if c := n.children[key]; c != nil {
			return c.match(rest)
		}
		return -1
	}
	if id := try(seg); id >= 0 {
		return id
	}
	if seg == "" {
		return -1
	}
	cls := classify(seg)
	if cls != seg {
		if id := try(cls); id >= 0 {
			return id
		}
	}
	if _, ext, ok := splitExt(seg); ok {
		if id := try(phName + ext); id >= 0 {
			return id
		}
	}
	// any other typed placeholder that still fits, e.g. a pattern with
	// {hex} and a segment that classified as {int}
	for key, c := range n.children {
		if key == phSlug || key == cls || !isPlaceholder(key) || strings.HasPrefix(key, phName) {
			continue
		}
		if segMatches(key, seg) {
			if id := c.match(rest); id >= 0 {
				return id
			}
		}
	}
	return try(phSlug)
}
