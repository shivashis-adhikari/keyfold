package cache

// w-tinylfu (einziger, friedman and manes, 2017), the policy behind
// caffeine and ristretto. a small lru window takes every new object; when
// the window overflows, its oldest entry has to beat main's eviction victim
// on estimated frequency to get in. main is a segmented lru: probation for
// new arrivals, protected for anything hit again.
//
// frequencies come from a count-min sketch with 4-bit counters that halve
// every 10 x width increments, so popularity from last week fades.
//
// sizing is in bytes: window 1%, protected 80% of main. with variable sizes
// a big candidate may have to beat several victims; it gets in only if it
// beats each one, which is how caffeine handles weighted entries too.
type tinylfu struct {
	a                          arena
	window, probation, protect list
	capacity, windowCap        int64
	mainCap, protectCap        int64
	sketch                     *sketch
}

const (
	queueWindow    = 0
	queueProbation = 1
	queueProtected = 2
)

func newTinyLFU(capacity int64, objects int) *tinylfu {
	w := capacity / 100
	if w < 1 {
		w = 1
	}
	main := capacity - w
	return &tinylfu{
		a: newArena(), window: newList(), probation: newList(), protect: newList(),
		capacity: capacity, windowCap: w, mainCap: main, protectCap: main * 8 / 10,
		sketch: newSketch(objects),
	}
}

func (c *tinylfu) Access(key uint64, size int64, now, expires int64) bool {
	c.sketch.add(key)
	if i, ok := c.a.index[key]; ok {
		n := &c.a.nodes[i]
		fresh := now < n.expires
		switch n.queue {
		case queueWindow:
			c.window.moveToFront(&c.a, i)
			if !fresh {
				c.window.refresh(&c.a, i, size, expires)
			}
		case queueProbation:
			c.probation.remove(&c.a, i)
			if !fresh {
				n.size, n.expires = size, expires
			}
			n.queue = queueProtected
			c.protect.pushFront(&c.a, i)
			c.demote()
		default:
			c.protect.moveToFront(&c.a, i)
			if !fresh {
				c.protect.refresh(&c.a, i, size, expires)
				c.demote()
			}
		}
		if fresh {
			return true
		}
		c.shrink()
		return false
	}
	if size > c.capacity {
		return false
	}
	i := c.a.alloc(key, size, expires)
	c.a.nodes[i].queue = queueWindow
	c.window.pushFront(&c.a, i)
	c.shrink()
	return false
}

// moves protected overflow back to probation
func (c *tinylfu) demote() {
	for c.protect.bytes > c.protectCap && c.protect.tail != nilIdx {
		t := c.protect.tail
		c.protect.remove(&c.a, t)
		c.a.nodes[t].queue = queueProbation
		c.probation.pushFront(&c.a, t)
	}
}

func (c *tinylfu) shrink() {
	for c.window.bytes > c.windowCap && c.window.tail != nilIdx {
		t := c.window.tail
		c.window.remove(&c.a, t)
		c.admit(t)
	}
	// a refresh in main can push the total over without touching the window
	for c.probation.bytes+c.protect.bytes > c.mainCap {
		v := c.victim()
		if v == nilIdx {
			break
		}
		c.drop(v)
	}
}

func (c *tinylfu) victim() int32 {
	if c.probation.tail != nilIdx {
		return c.probation.tail
	}
	return c.protect.tail
}

func (c *tinylfu) drop(i int32) {
	switch c.a.nodes[i].queue {
	case queueProbation:
		c.probation.remove(&c.a, i)
	case queueProtected:
		c.protect.remove(&c.a, i)
	default:
		c.window.remove(&c.a, i)
	}
	c.a.release(i)
}

func (c *tinylfu) admit(cand int32) {
	n := &c.a.nodes[cand]
	if n.size > c.mainCap {
		c.a.release(cand)
		return
	}
	candFreq := c.sketch.estimate(n.key)
	for c.probation.bytes+c.protect.bytes+n.size > c.mainCap {
		v := c.victim()
		if v == nilIdx {
			break
		}
		if candFreq <= c.sketch.estimate(c.a.nodes[v].key) {
			c.a.release(cand)
			return
		}
		c.drop(v)
	}
	n.queue = queueProbation
	c.probation.pushFront(&c.a, cand)
}

func (c *tinylfu) Len() int    { return c.window.n + c.probation.n + c.protect.n }
func (c *tinylfu) Used() int64 { return c.window.bytes + c.probation.bytes + c.protect.bytes }

// count-min sketch, depth 4, counters saturate at 15.
type sketch struct {
	rows  [4][]uint8
	mask  uint64
	adds  int
	reset int
}

func newSketch(objects int) *sketch {
	w := 64
	for w < objects && w < 1<<24 {
		w <<= 1
	}
	s := &sketch{mask: uint64(w - 1), reset: 10 * w}
	for i := range s.rows {
		s.rows[i] = make([]uint8, w)
	}
	return s
}

var seeds = [4]uint64{0x9e3779b97f4a7c15, 0xbf58476d1ce4e5b9, 0x94d049bb133111eb, 0x2545f4914f6cdd1d}

func (s *sketch) slot(key uint64, row int) uint64 {
	h := (key ^ seeds[row]) * 0xff51afd7ed558ccd
	h ^= h >> 33
	return h & s.mask
}

func (s *sketch) add(key uint64) {
	for r := range s.rows {
		if c := &s.rows[r][s.slot(key, r)]; *c < 15 {
			*c++
		}
	}
	s.adds++
	if s.adds >= s.reset {
		for r := range s.rows {
			for i := range s.rows[r] {
				s.rows[r][i] >>= 1
			}
		}
		s.adds /= 2
	}
}

func (s *sketch) estimate(key uint64) uint8 {
	m := uint8(15)
	for r := range s.rows {
		if c := s.rows[r][s.slot(key, r)]; c < m {
			m = c
		}
	}
	return m
}
