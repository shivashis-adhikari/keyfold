// package cache has byte-capacity eviction policies for trace replay.
//
// keys are 64-bit hashes and objects are just sizes. every policy stores its
// entries in one slice with int32 links instead of pointers, so a replay over
// millions of objects doesn't spend its time in the garbage collector.
package cache

import (
	"fmt"
	"strings"
)

// a byte-capacity cache over hashed keys.
type Cache interface {
	// looks key up at time now. a fresh entry is a hit. otherwise (absent
	// or expired) the object is admitted with the given size and expiry,
	// subject to the policy, and the access counts as a miss.
	Access(key uint64, size int64, now, expires int64) bool
	Len() int
	Used() int64
}

// policy names the constructor accepts, in the order reports show them.
var Policies = []string{"lru", "fifo", "sieve", "s3fifo", "tinylfu"}

// builds a cache. objects is a rough guess at how many objects fit,
// only tinylfu uses it, to size its sketch.
func New(policy string, capacity int64, objects int) (Cache, error) {
	if capacity <= 0 {
		return nil, fmt.Errorf("cache capacity must be positive, got %d", capacity)
	}
	switch strings.ToLower(policy) {
	case "lru":
		return newLRU(capacity), nil
	case "fifo":
		return newFIFO(capacity), nil
	case "sieve":
		return newSieve(capacity), nil
	case "s3fifo", "s3-fifo":
		return newS3FIFO(capacity), nil
	case "tinylfu", "w-tinylfu", "wtinylfu":
		return newTinyLFU(capacity, objects), nil
	}
	return nil, fmt.Errorf("unknown policy %q (have %s)", policy, strings.Join(Policies, ", "))
}

const nilIdx = -1

type node struct {
	key        uint64
	size       int64
	expires    int64
	prev, next int32 // prev is towards the head (newer), next towards the tail
	queue      uint8
	freq       uint8
	visited    bool
}

// slab of nodes plus the key index.
type arena struct {
	nodes []node
	free  []int32
	index map[uint64]int32
}

func newArena() arena { return arena{index: make(map[uint64]int32)} }

func (a *arena) alloc(key uint64, size, expires int64) int32 {
	var i int32
	if n := len(a.free); n > 0 {
		i = a.free[n-1]
		a.free = a.free[:n-1]
	} else {
		a.nodes = append(a.nodes, node{})
		i = int32(len(a.nodes) - 1)
	}
	a.nodes[i] = node{key: key, size: size, expires: expires, prev: nilIdx, next: nilIdx}
	a.index[key] = i
	return i
}

func (a *arena) release(i int32) {
	delete(a.index, a.nodes[i].key)
	a.free = append(a.free, i)
}

// a doubly linked list threaded through the arena. head is newest.
type list struct {
	head, tail int32
	bytes      int64
	n          int
}

func newList() list { return list{head: nilIdx, tail: nilIdx} }

func (l *list) pushFront(a *arena, i int32) {
	n := &a.nodes[i]
	n.prev, n.next = nilIdx, l.head
	if l.head != nilIdx {
		a.nodes[l.head].prev = i
	} else {
		l.tail = i
	}
	l.head = i
	l.bytes += n.size
	l.n++
}

func (l *list) remove(a *arena, i int32) {
	n := &a.nodes[i]
	if n.prev != nilIdx {
		a.nodes[n.prev].next = n.next
	} else {
		l.head = n.next
	}
	if n.next != nilIdx {
		a.nodes[n.next].prev = n.prev
	} else {
		l.tail = n.prev
	}
	n.prev, n.next = nilIdx, nilIdx
	l.bytes -= n.size
	l.n--
}

func (l *list) moveToFront(a *arena, i int32) {
	if l.head == i {
		return
	}
	l.remove(a, i)
	l.pushFront(a, i)
}

// an expired entry gets refetched in place: same slot, new size and
// expiry. this is what a cdn revalidating a stale object looks like from
// the eviction policy's point of view.
func (l *list) refresh(a *arena, i int32, size, expires int64) {
	n := &a.nodes[i]
	l.bytes += size - n.size
	n.size, n.expires = size, expires
}

// an unbounded cache, the upper bound for any policy at any size: only
// first requests and expiries miss.
type Infinite struct {
	exp map[uint64]int64
}

func NewInfinite() *Infinite { return &Infinite{exp: make(map[uint64]int64)} }

func (c *Infinite) Access(key uint64, _ int64, now, expires int64) bool {
	if e, ok := c.exp[key]; ok && now < e {
		return true
	}
	c.exp[key] = expires
	return false
}

func (c *Infinite) Len() int    { return len(c.exp) }
func (c *Infinite) Used() int64 { return 0 }
