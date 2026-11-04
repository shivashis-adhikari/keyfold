package cache

// s3-fifo (yang et al., sosp '23). three fifo queues: a small one holding
// about 10% of the bytes, a main one, and a ghost queue that remembers keys
// recently evicted from small.
//
// new objects land in small. most of them are never asked for again and
// leave quickly, which is the whole point: one-hit wonders never get to
// push useful objects out of main. an object hit at least twice while in
// small moves to main. a miss on a key the ghost remembers goes straight to
// main. main evicts fifo-style, but reinserts anything hit since its last
// pass, decrementing its 2-bit counter.
//
// sizes are bytes here, not object counts, so "10%" and the ghost budget
// are in bytes too. the paper's ghost holds as many entries as main does;
// a byte budget equal to main's capacity is the closest thing when objects
// vary in size.
type s3fifo struct {
	a               arena
	small, main     list
	ghost           ghost
	capacity        int64
	smallCap        int64
	moveToMainAfter uint8
}

const (
	queueSmall = 0
	queueMain  = 1
	maxFreq    = 3
)

func newS3FIFO(capacity int64) *s3fifo {
	small := capacity / 10
	if small < 1 {
		small = 1
	}
	return &s3fifo{
		a: newArena(), small: newList(), main: newList(),
		ghost:           newGhost(capacity - small),
		capacity:        capacity,
		smallCap:        small,
		moveToMainAfter: 2,
	}
}

func (c *s3fifo) Access(key uint64, size int64, now, expires int64) bool {
	if i, ok := c.a.index[key]; ok {
		n := &c.a.nodes[i]
		if n.freq < maxFreq {
			n.freq++
		}
		if now < n.expires {
			return true
		}
		if n.queue == queueSmall {
			c.small.refresh(&c.a, i, size, expires)
		} else {
			c.main.refresh(&c.a, i, size, expires)
		}
		c.evict()
		return false
	}
	if size > c.capacity {
		return false
	}
	i := c.a.alloc(key, size, expires)
	if c.ghost.remove(key) {
		c.a.nodes[i].queue = queueMain
		c.main.pushFront(&c.a, i)
	} else {
		c.a.nodes[i].queue = queueSmall
		c.small.pushFront(&c.a, i)
	}
	c.evict()
	return false
}

func (c *s3fifo) evict() {
	for c.small.bytes+c.main.bytes > c.capacity {
		if (c.small.bytes > c.smallCap || c.main.n == 0) && c.small.n > 0 {
			c.evictSmall()
		} else if c.main.n > 0 {
			c.evictMain()
		} else {
			return
		}
	}
}

// evicts one object out of small, possibly after moving several to main.
func (c *s3fifo) evictSmall() {
	for c.small.tail != nilIdx {
		t := c.small.tail
		n := &c.a.nodes[t]
		c.small.remove(&c.a, t)
		if n.freq >= c.moveToMainAfter {
			n.freq = 0
			n.queue = queueMain
			c.main.pushFront(&c.a, t)
			continue
		}
		c.ghost.add(n.key, n.size)
		c.a.release(t)
		return
	}
}

func (c *s3fifo) evictMain() {
	for c.main.tail != nilIdx {
		t := c.main.tail
		n := &c.a.nodes[t]
		if n.freq > 0 {
			n.freq--
			c.main.moveToFront(&c.a, t)
			continue
		}
		c.main.remove(&c.a, t)
		c.a.release(t)
		return
	}
}

func (c *s3fifo) Len() int    { return c.small.n + c.main.n }
func (c *s3fifo) Used() int64 { return c.small.bytes + c.main.bytes }

// fifo of evicted keys with a byte budget. removal is lazy: the map is
// the source of truth and stale queue entries are skipped when popped.
type ghost struct {
	q      []ghostEntry
	head   int
	live   map[uint64]ghostEntry
	bytes  int64
	budget int64
	seq    uint64
}

type ghostEntry struct {
	key  uint64
	size int64
	seq  uint64
}

func newGhost(budget int64) ghost {
	if budget < 1 {
		budget = 1
	}
	return ghost{live: make(map[uint64]ghostEntry), budget: budget}
}

func (g *ghost) add(key uint64, size int64) {
	if old, ok := g.live[key]; ok {
		g.bytes -= old.size
	}
	g.seq++
	e := ghostEntry{key: key, size: size, seq: g.seq}
	g.live[key] = e
	g.q = append(g.q, e)
	g.bytes += size
	for g.bytes > g.budget && g.head < len(g.q) {
		old := g.q[g.head]
		g.head++
		if cur, ok := g.live[old.key]; ok && cur.seq == old.seq {
			delete(g.live, old.key)
			g.bytes -= old.size
		}
	}
	if g.head > 1024 && g.head*2 > len(g.q) {
		n := copy(g.q, g.q[g.head:])
		g.q = g.q[:n]
		g.head = 0
	}
}

func (g *ghost) remove(key uint64) bool {
	e, ok := g.live[key]
	if !ok {
		return false
	}
	delete(g.live, key)
	g.bytes -= e.size
	return true
}
