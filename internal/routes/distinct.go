package routes

import (
	"math"
	"math/bits"
)

// counts distinct 64-bit hashes. exact up to a couple thousand, then a
// hyperloglog with 2^12 registers (about 1.6% standard error, 4kb). per-route url
// counts on a busy site run into the millions, and we keep a few of these
// for every route and every param.
type distinct struct {
	exact map[uint64]struct{}
	regs  []uint8
}

const (
	exactLimit = 2048
	hllP       = 12
	hllM       = 1 << hllP
)

func (d *distinct) add(h uint64) {
	if d.regs == nil {
		if d.exact == nil {
			d.exact = make(map[uint64]struct{}, 8)
		}
		d.exact[h] = struct{}{}
		if len(d.exact) > exactLimit {
			d.toHLL()
		}
		return
	}
	d.addHLL(h)
}

func (d *distinct) toHLL() {
	d.regs = make([]uint8, hllM)
	for h := range d.exact {
		d.addHLL(h)
	}
	d.exact = nil
}

func (d *distinct) addHLL(h uint64) {
	h = mix(h)
	idx := h >> (64 - hllP)
	rank := uint8(bits.LeadingZeros64(h<<hllP|1<<(hllP-1)) + 1)
	if rank > d.regs[idx] {
		d.regs[idx] = rank
	}
}

func (d *distinct) count() int64 {
	if d.regs == nil {
		return int64(len(d.exact))
	}
	sum, zeros := 0.0, 0
	for _, r := range d.regs {
		sum += 1 / float64(uint64(1)<<r)
		if r == 0 {
			zeros++
		}
	}
	m := float64(hllM)
	est := 0.7213 / (1 + 1.079/m) * m * m / sum
	if est <= 2.5*m && zeros > 0 {
		est = m * math.Log(m/float64(zeros))
	}
	return int64(est + 0.5)
}

func (d *distinct) merge(o *distinct) {
	if o == nil {
		return
	}
	if o.regs == nil {
		for h := range o.exact {
			d.add(h)
		}
		return
	}
	if d.regs == nil {
		d.toHLL()
	}
	for i, r := range o.regs {
		if r > d.regs[i] {
			d.regs[i] = r
		}
	}
}

// splitmix64's finaliser. fnv's low bits are fine but its high bits, which
// pick the register, are not great for short inputs.
func mix(x uint64) uint64 {
	x ^= x >> 30
	x *= 0xbf58476d1ce4e5b9
	x ^= x >> 27
	x *= 0x94d049bb133111eb
	x ^= x >> 31
	return x
}

func hashString(s string) uint64 {
	// fnv-1a, inlined so the hot path doesn't allocate a hasher
	h := uint64(14695981039346656037)
	for i := 0; i < len(s); i++ {
		h ^= uint64(s[i])
		h *= 1099511628211
	}
	return h
}

// the 64-bit hash used for keys and counters across keyfold.
func HashString(s string) uint64 { return hashString(s) }
