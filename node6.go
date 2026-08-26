package nradix

import (
	"math/bits"
	"unsafe"
)

type node6[T any] struct {
	left, right *node6[T]
	prefix      uint128
	plen        uint8
	set         bool
	val         T
}

func (n *node6[T]) getNext(right bool) *node6[T] {
	return *(**node6[T])(unsafe.Add(unsafe.Pointer(n), b2u(right)*sizeOfUintPtr))
}

func (n *node6[T]) setNext(right bool, nn *node6[T]) *node6[T] {
	*(**node6[T])(unsafe.Add(unsafe.Pointer(n), b2u(right)*sizeOfUintPtr)) = nn
	return nn
}

func (n *node6[T]) setValue(val T) {
	n.set = true
	n.val = val
}

func (n *node6[T]) unsetValue() {
	var zero T
	n.set = false
	n.val = zero
}

func (n *node6[T]) forks() bool {
	return n.left != nil && n.right != nil
}

func (n *node6[T]) onlyChild() *node6[T] {
	if n.left != nil {
		return n.left
	}
	return n.right
}

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
