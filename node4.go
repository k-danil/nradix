package nradix

import (
	"math/bits"
	"unsafe"
)

type node4[T any] struct {
	left, right *node4[T]
	prefix      uint32
	plen        uint8
	set         bool
	val         T
}

func (n *node4[T]) getNext(right bool) *node4[T] {
	return *(**node4[T])(unsafe.Add(unsafe.Pointer(n), b2u(right)*sizeOfUintPtr))
}

func (n *node4[T]) setNext(right bool, nn *node4[T]) *node4[T] {
	*(**node4[T])(unsafe.Add(unsafe.Pointer(n), b2u(right)*sizeOfUintPtr)) = nn
	return nn
}

func (n *node4[T]) setValue(val T) {
	n.set = true
	n.val = val
}

func (n *node4[T]) unsetValue() {
	var zero T
	n.set = false
	n.val = zero
}

func (n *node4[T]) forks() bool {
	return n.left != nil && n.right != nil
}

func (n *node4[T]) onlyChild() *node4[T] {
	if n.left != nil {
		return n.left
	}
	return n.right
}

func mask4(plen uint8) uint32 {
	return ^uint32(0) << (ipv4MaxMaskLength - plen)
}

func plenOf4(mask uint32) uint8 {
	return uint8(bits.OnesCount32(mask))
}

func cpl4(a, b uint32) uint8 {
	return uint8(bits.LeadingZeros32(a ^ b))
}

func bit4(ip uint32, at uint8) bool {
	return ip&(uint32StartBit>>at) != 0
}
