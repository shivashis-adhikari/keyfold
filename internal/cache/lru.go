package cache

// lru and fifo share everything except what a hit does.
type queueCache struct {
	a        arena
	l        list
	capacity int64
	promote  bool
}

func newLRU(capacity int64) *queueCache {
	return &queueCache{a: newArena(), l: newList(), capacity: capacity, promote: true}
}

func newFIFO(capacity int64) *queueCache {
	return &queueCache{a: newArena(), l: newList(), capacity: capacity}
}

func (c *queueCache) Access(key uint64, size int64, now, expires int64) bool {
	if i, ok := c.a.index[key]; ok {
		if c.promote {
			c.l.moveToFront(&c.a, i)
		}
		if now < c.a.nodes[i].expires {
			return true
		}
		c.l.refresh(&c.a, i, size, expires)
		c.evict()
		return false
	}
	if size > c.capacity {
		return false
	}
	c.l.pushFront(&c.a, c.a.alloc(key, size, expires))
	c.evict()
	return false
}

func (c *queueCache) evict() {
	for c.l.bytes > c.capacity && c.l.tail != nilIdx {
		t := c.l.tail
		c.l.remove(&c.a, t)
		c.a.release(t)
	}
}

func (c *queueCache) Len() int    { return c.l.n }
func (c *queueCache) Used() int64 { return c.l.bytes }

// sieve (zhang et al., nsdi '24): one fifo queue and a hand. a hit only
// sets a bit, nothing moves. eviction walks the hand from the tail towards
// the head, clearing bits, and evicts the first unvisited entry. new
// objects go in at the head, so the hand reaches them last.
type sieve struct {
	a        arena
	l        list
	capacity int64
	hand     int32
}

func newSieve(capacity int64) *sieve {
	return &sieve{a: newArena(), l: newList(), capacity: capacity, hand: nilIdx}
}

func (c *sieve) Access(key uint64, size int64, now, expires int64) bool {
	if i, ok := c.a.index[key]; ok {
		n := &c.a.nodes[i]
		n.visited = true
		if now < n.expires {
			return true
		}
		c.l.refresh(&c.a, i, size, expires)
		c.evict()
		return false
	}
	if size > c.capacity {
		return false
	}
	c.l.pushFront(&c.a, c.a.alloc(key, size, expires))
	c.evict()
	return false
}

func (c *sieve) evict() {
	for c.l.bytes > c.capacity && c.l.tail != nilIdx {
		o := c.hand
		if o == nilIdx {
			o = c.l.tail
		}
		for c.a.nodes[o].visited {
			c.a.nodes[o].visited = false
			o = c.a.nodes[o].prev
			if o == nilIdx {
				o = c.l.tail
			}
		}
		c.hand = c.a.nodes[o].prev
		c.l.remove(&c.a, o)
		c.a.release(o)
	}
}

func (c *sieve) Len() int    { return c.l.n }
func (c *sieve) Used() int64 { return c.l.bytes }
