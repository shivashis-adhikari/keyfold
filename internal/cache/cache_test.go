package cache

import (
	"math"
	"math/rand/v2"
	"testing"
)

const never = math.MaxInt64

func run(c Cache, keys ...uint64) string {
	out := make([]byte, len(keys))
	for i, k := range keys {
		if c.Access(k, 1, int64(i), never) {
			out[i] = 'h'
		} else {
			out[i] = '.'
		}
	}
	return string(out)
}

func TestLRU(t *testing.T) {
	c := newLRU(3)
	// 1 2 3, touch 1, add 4 (evicts 2), 2 misses and evicts 3, 1 is
	// still there, 3 is not
	if got := run(c, 1, 2, 3, 1, 4, 2, 1, 3); got != "...h..h." {
		t.Errorf("lru = %s", got)
	}
}

func TestFIFO(t *testing.T) {
	c := newFIFO(3)
	// a hit doesn't save 1 from being first out
	if got := run(c, 1, 2, 3, 1, 4, 1); got != "...h.." {
		t.Errorf("fifo = %s", got)
	}
}

func TestSieve(t *testing.T) {
	c := newSieve(3)
	// a b c, hit a. inserting d: the hand starts at the tail (a), clears
	// its bit, moves on to b and evicts it. then e evicts c, the next
	// unvisited entry after the hand.
	got := run(c, 1, 2, 3, 1, 4, 5, 1, 2)
	if got != "...h..h." {
		t.Errorf("sieve = %s", got)
	}
	if c.Len() != 3 {
		t.Errorf("len = %d", c.Len())
	}
}

func TestS3FIFOGhost(t *testing.T) {
	c := newS3FIFO(10) // small holds 1 byte
	// 1 enters small, 2 pushes it out to the ghost queue. asking for 1
	// again is a miss, but it goes straight to main this time.
	c.Access(1, 1, 0, never)
	for k := uint64(2); k <= 11; k++ {
		c.Access(k, 1, 0, never)
	}
	if _, ok := c.a.index[1]; ok {
		t.Fatal("1 should have been evicted from small")
	}
	if _, ok := c.ghost.live[1]; !ok {
		t.Fatal("1 should be in the ghost queue")
	}
	c.Access(1, 1, 0, never)
	if c.a.nodes[c.a.index[1]].queue != queueMain {
		t.Error("ghost hit should insert into main")
	}
}

func TestTTL(t *testing.T) {
	for _, p := range Policies {
		c, _ := New(p, 100, 10)
		c.Access(1, 10, 0, 50)
		if !c.Access(1, 10, 10, 50) {
			t.Errorf("%s: fresh entry should hit", p)
		}
		if c.Access(1, 10, 60, 120) {
			t.Errorf("%s: expired entry should miss", p)
		}
		if !c.Access(1, 10, 70, 120) {
			t.Errorf("%s: refetched entry should hit again", p)
		}
	}
}

func TestOversizedObjects(t *testing.T) {
	for _, p := range Policies {
		c, _ := New(p, 100, 10)
		c.Access(1, 101, 0, never)
		if c.Len() != 0 || c.Used() != 0 {
			t.Errorf("%s: object bigger than the cache was admitted", p)
		}
	}
}

// random traces with random sizes. checks the byte budget after every
// access, that bookkeeping matches the index, and that no policy beats an
// infinite cache.
func TestInvariants(t *testing.T) {
	for _, p := range Policies {
		for seed := uint64(1); seed <= 3; seed++ {
			r := rand.New(rand.NewPCG(seed, seed))
			capacity := int64(500 + r.IntN(5000))
			c, _ := New(p, capacity, 64)
			inf := NewInfinite()
			hits, infHits := 0, 0
			for i := 0; i < 20000; i++ {
				key := uint64(r.IntN(300))
				if r.IntN(10) == 0 {
					key = uint64(1000 + i) // one-hit wonder
				}
				size := int64(1 + key%97)
				exp := int64(never)
				if key%5 == 0 {
					exp = int64(i + 500)
				}
				if c.Access(key, size, int64(i), exp) {
					hits++
				}
				if inf.Access(key, size, int64(i), exp) {
					infHits++
				}
				if c.Used() > capacity {
					t.Fatalf("%s seed %d: used %d > capacity %d at %d", p, seed, c.Used(), capacity, i)
				}
			}
			if hits > infHits {
				t.Errorf("%s: %d hits beats the infinite cache's %d", p, hits, infHits)
			}
			checkIndex(t, p, c)
		}
	}
}

func checkIndex(t *testing.T, name string, c Cache) {
	t.Helper()
	var a *arena
	var lists []*list
	switch x := c.(type) {
	case *queueCache:
		a, lists = &x.a, []*list{&x.l}
	case *sieve:
		a, lists = &x.a, []*list{&x.l}
	case *s3fifo:
		a, lists = &x.a, []*list{&x.small, &x.main}
	case *tinylfu:
		a, lists = &x.a, []*list{&x.window, &x.probation, &x.protect}
	}
	n, bytes := 0, int64(0)
	for _, l := range lists {
		for i := l.head; i != nilIdx; i = a.nodes[i].next {
			n++
			bytes += a.nodes[i].size
			if a.index[a.nodes[i].key] != i {
				t.Fatalf("%s: index out of sync for key %d", name, a.nodes[i].key)
			}
		}
	}
	if n != len(a.index) || n != c.Len() || bytes != c.Used() {
		t.Errorf("%s: walked %d entries / %d bytes, index %d, len %d, used %d", name, n, bytes, len(a.index), c.Len(), c.Used())
	}
}

// with room for everything, every policy should behave like the infinite
// cache.
func TestBigEnoughCacheIsInfinite(t *testing.T) {
	r := rand.New(rand.NewPCG(9, 9))
	keys := make([]uint64, 50000)
	for i := range keys {
		keys[i] = uint64(r.IntN(2000))
	}
	inf := NewInfinite()
	want := 0
	for i, k := range keys {
		if inf.Access(k, 10, int64(i), never) {
			want++
		}
	}
	for _, p := range Policies {
		c, _ := New(p, 2000*10*2, 2000)
		got := 0
		for i, k := range keys {
			if c.Access(k, 10, int64(i), never) {
				got++
			}
		}
		// tinylfu may reject a few candidates while its window churns, so
		// give it a little slack
		if got != want && !(p == "tinylfu" && got > want*99/100) {
			t.Errorf("%s: %d hits, infinite cache has %d", p, got, want)
		}
	}
}

// the scan-resistance argument for s3-fifo and tinylfu: a steady hot set
// plus a stream of objects nobody asks for twice. lru lets the stream flush
// the hot set; the frequency-aware policies shouldn't.
func TestScanResistance(t *testing.T) {
	ratio := map[string]float64{}
	for _, p := range []string{"lru", "s3fifo", "tinylfu", "sieve"} {
		c, _ := New(p, 1000, 1000)
		r := rand.New(rand.NewPCG(5, 5))
		hits, n := 0, 0
		next := uint64(1 << 32)
		for i := 0; i < 200000; i++ {
			var k uint64
			if r.IntN(2) == 0 {
				k = uint64(r.IntN(800)) // hot set, fits in the cache
			} else {
				k = next // scan
				next++
			}
			hit := c.Access(k, 1, int64(i), never)
			if k < 800 {
				n++
				if hit {
					hits++
				}
			}
		}
		ratio[p] = float64(hits) / float64(n)
	}
	t.Logf("hot-set hit ratio under a scan: %v", ratio)
	for _, p := range []string{"s3fifo", "tinylfu", "sieve"} {
		if ratio[p] <= ratio["lru"]+0.05 {
			t.Errorf("%s (%.3f) should beat lru (%.3f) clearly", p, ratio[p], ratio["lru"])
		}
	}
}

func TestSketch(t *testing.T) {
	s := newSketch(1000)
	for i := 0; i < 10; i++ {
		s.add(42)
	}
	s.add(7)
	if s.estimate(42) < 10 || s.estimate(7) < 1 || s.estimate(7) > 3 {
		t.Errorf("estimates: 42=%d 7=%d", s.estimate(42), s.estimate(7))
	}
	// aging halves everything
	for i := 0; i < s.reset; i++ {
		s.add(uint64(1000000 + i))
	}
	if e := s.estimate(42); e > 7 {
		t.Errorf("42 should have aged, estimate %d", e)
	}
}

func TestNewErrors(t *testing.T) {
	if _, err := New("arc", 10, 1); err == nil {
		t.Error("unknown policy should fail")
	}
	if _, err := New("lru", 0, 1); err == nil {
		t.Error("zero capacity should fail")
	}
}

func BenchmarkPolicies(b *testing.B) {
	r := rand.New(rand.NewPCG(1, 2))
	keys := make([]uint64, 1<<20)
	sizes := make([]int64, len(keys))
	for i := range keys {
		// zipf-ish: square a uniform draw
		u := r.Float64()
		keys[i] = uint64(u * u * 200000)
		sizes[i] = 1000 + int64(keys[i]%50000)
	}
	for _, p := range Policies {
		b.Run(p, func(b *testing.B) {
			c, _ := New(p, 200000*5000, 20000)
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				j := i & (len(keys) - 1)
				c.Access(keys[j], sizes[j], int64(i), never)
			}
		})
	}
}
