package normalize

import (
	"bytes"
	"sort"
	"strconv"
)

// a bag of words from a normalised body.
type Tokens map[string]int

func Tokenize(b []byte) Tokens {
	t := make(Tokens, len(b)/8)
	for _, f := range bytes.FieldsFunc(b, notWord) {
		t[string(f)]++
	}
	return t
}

func notWord(r rune) bool {
	return !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_' || r > 127)
}

// changed returns tokens whose counts differ between a and b.
func changed(a, b Tokens) map[string]bool {
	out := map[string]bool{}
	for k, n := range a {
		if b[k] != n {
			out[k] = true
		}
	}
	for k, n := range b {
		if a[k] != n {
			out[k] = true
		}
	}
	return out
}

// learns which tokens move between responses to the same request.
// feed it every baseline fetch; tokens that differ between any two of them
// are noise for this url.
type Volatile struct {
	bases []Tokens
	set   map[string]bool
}

func (v *Volatile) Add(t Tokens) {
	if v.set == nil {
		v.set = map[string]bool{}
	}
	for _, b := range v.bases {
		for k := range changed(b, t) {
			v.set[k] = true
		}
	}
	v.bases = append(v.bases, t)
}

// marks everything that differs between two responses to the same request
// as noise, without making either of them a baseline.
func (v *Volatile) Learn(a, b Tokens) {
	if v.set == nil {
		v.set = map[string]bool{}
	}
	for k := range changed(a, b) {
		v.set[k] = true
	}
}

// adds tokens to the noise set directly, for a model loaded from disk.
func (v *Volatile) Mark(tokens []string) {
	if v.set == nil {
		v.set = map[string]bool{}
	}
	for _, t := range tokens {
		v.set[t] = true
	}
}

// the noise set, sorted.
func (v *Volatile) Tokens() []string {
	out := make([]string, 0, len(v.set))
	for t := range v.set {
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}

func (v *Volatile) Len() int { return len(v.set) }

// returns tokens that differ between t and the closest baseline and
// are not known to be volatile, sorted, at most limit of them. an empty
// result means t looks like just another baseline.
//
// this errs towards reporting a difference: content that rotates but never
// rotated during the baselines shows up here. for cache keys that is the
// cheap mistake (a param kept that could have been dropped), the other one
// serves wrong pages.
func (v *Volatile) Residual(t Tokens, limit int) []string {
	var best []string
	for i, b := range v.bases {
		var out []string
		for k := range changed(b, t) {
			if !v.set[k] {
				out = append(out, k)
			}
		}
		if i == 0 || len(out) < len(best) {
			best = out
		}
		if len(best) == 0 {
			return nil
		}
	}
	sort.Strings(best)
	if limit > 0 && len(best) > limit {
		best = best[:limit]
	}
	return best
}

// a coarse description of tokens that contain digits: "d6" for six
// digits, "h16" for sixteen hex chars, "m12" for anything else alphanumeric
// with a digit in it. ids, counters and timestamps keep their shape when
// their value changes. tokens without digits (words) have no shape: a
// changed word is never written off as noise this way.
func Shape(tok string) string {
	digits, hex := 0, true
	for i := 0; i < len(tok); i++ {
		c := tok[i]
		switch {
		case c >= '0' && c <= '9':
			digits++
		case c >= 'a' && c <= 'f', c >= 'A' && c <= 'F':
		default:
			hex = false
		}
	}
	switch {
	case digits == 0:
		return ""
	case digits == len(tok):
		return "d" + strconv.Itoa(len(tok))
	case hex:
		return "h" + strconv.Itoa(len(tok))
	}
	return "m" + strconv.Itoa(len(tok))
}
