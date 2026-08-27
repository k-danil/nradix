package nradix

import (
	"math/bits"
	"unsafe"
)

const sizeOfUintPtr = uint8(unsafe.Sizeof(uintptr(0)))

func b2u(b bool) uint8 {
	if b {
		return 1
	}
	return 0
}

type node[T any] struct {
	left, right *node[T]
	prefix      uint128
	plen        uint8
	set         bool
	// cplen mirrors {left,right}.plen: find reads the child's bit index from the
	// current cache line instead of waiting for the child's. A linked node's plen
	// never changes, so setNext keeps the mirror exact.
	cplen [2]uint8
	val   T
}

func (n *node[T]) getNext(right bool) *node[T] {
	return *(**node[T])(unsafe.Add(unsafe.Pointer(n), b2u(right)*sizeOfUintPtr))
}

func (n *node[T]) nextPlen(right bool) uint8 {
	return n.cplen[b2u(right)]
}

func (n *node[T]) setNext(right bool, nn *node[T]) *node[T] {
	*(**node[T])(unsafe.Add(unsafe.Pointer(n), b2u(right)*sizeOfUintPtr)) = nn
	if nn != nil {
		n.cplen[b2u(right)] = nn.plen
	}
	return nn
}

func (n *node[T]) setValue(val T) {
	n.set = true
	n.val = val
}

func (n *node[T]) unsetValue() {
	var zero T
	n.set = false
	n.val = zero
}

func (n *node[T]) forks() bool {
	return n.left != nil && n.right != nil
}

func (n *node[T]) onlyChild() *node[T] {
	if n.left != nil {
		return n.left
	}
	return n.right
}

var fullMask128 = uint128{^uint64(0), ^uint64(0)}

func mask128(plen uint8) uint128 {
	if plen <= ipv6HalfMaskLength {
		return uint128{hi: ^uint64(0) << (ipv6HalfMaskLength - plen)}
	}
	return uint128{^uint64(0), ^uint64(0) << (ipv6MaxMaskLength - plen)}
}

func plenOf128(mask uint128) uint8 {
	return uint8(bits.OnesCount64(mask.hi) + bits.OnesCount64(mask.lo))
}

func cpl128(a, b uint128) uint8 {
	if x := a.hi ^ b.hi; x != 0 {
		return uint8(bits.LeadingZeros64(x))
	}
	if x := a.lo ^ b.lo; x != 0 {
		return ipv6HalfMaskLength + uint8(bits.LeadingZeros64(x))
	}
	return ipv6MaxMaskLength
}

func bit128(ip uint128, at uint8) bool {
	if at < ipv6HalfMaskLength {
		return ip.hi&(uint128StartBit>>at) != 0
	}
	return ip.lo&(uint128StartBit>>(at-ipv6HalfMaskLength)) != 0
}

func and128(a, b uint128) uint128 {
	return uint128{a.hi & b.hi, a.lo & b.lo}
}
