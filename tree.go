// Copyright (C) 2015 Alex Sergeyev
// This project is licensed under the terms of the MIT license.
// Read LICENSE file for information for all notices and permissions.

package nradix

import (
	"errors"
)

// Tree implements radix tree for working with IP/mask. Thread safety is not guaranteed, you should choose your own style of protecting safety of operations.
type Tree[T any] struct {
	root4  *node4[T]
	free4  *node4[T]
	alloc4 []node4[T]

	root6  *node6[T]
	free6  *node6[T]
	alloc6 []node6[T]

	ipv6 bool
}

const (
	uint32StartBit  uint32 = 1 << 31
	uint128StartBit uint64 = 1 << 63

	allocChunkGrowth = 200
)

type uint128 struct {
	hi, lo uint64
}

var (
	ErrNodeBusy = errors.New("node busy")
	ErrNotFound = errors.New("no such node")
	ErrBadIP    = errors.New("bad IP address or mask")
)

// NewTree creates Tree.
func NewTree[T any](preallocate uint64, ipv6 bool) (t *Tree[T]) {
	t = &Tree[T]{
		ipv6: ipv6,
	}
	if ipv6 {
		if preallocate > 0 {
			t.alloc6 = make([]node6[T], 0, preallocate)
		}
		t.root6 = t.newNode6()
		return
	}
	if preallocate > 0 {
		t.alloc4 = make([]node4[T], 0, preallocate)
	}
	t.root4 = t.newNode4()
	return
}

func (t *Tree[T]) AddCIDR(cidr string, val T) error {
	return t.setInternal(cidr, val, false)
}

func (t *Tree[T]) SetCIDR(cidr string, val T) error {
	return t.setInternal(cidr, val, true)
}

func (t *Tree[T]) setInternal(cidr string, val T, overwrite bool) error {
	if t.ipv6 {
		ip, mask, err := parseCIDR6(cidr)
		if err != nil {
			return err
		}
		return t.insert128(ip, mask, val, overwrite)
	}

	ip, mask, err := parseCIDR4(StringToBytes(cidr))
	if err != nil {
		return err
	}
	return t.insert32(ip, mask, val, overwrite)
}

func (t *Tree[T]) DeleteWholeRangeCIDR(cidr string) error {
	return t.deleteInternal(cidr, true)
}

func (t *Tree[T]) DeleteCIDR(cidr string) error {
	return t.deleteInternal(cidr, false)
}

func (t *Tree[T]) deleteInternal(cidr string, wholeRange bool) error {
	if t.ipv6 {
		ip, mask, err := parseCIDR6(cidr)
		if err != nil {
			return err
		}
		return t.delete128(ip, mask, wholeRange)
	}

	ip, mask, err := parseCIDR4(StringToBytes(cidr))
	if err != nil {
		return err
	}
	return t.delete32(ip, mask, wholeRange)
}

func (t *Tree[T]) FindCIDR(cidr string) (T, error) {
	var found bool
	var val T
	if t.ipv6 {
		ip, mask, err := parseCIDR6(cidr)
		if err != nil {
			return val, err
		}
		val, found = t.find128(ip, mask)
	} else {
		ip, mask, err := parseCIDR4(StringToBytes(cidr))
		if err != nil {
			return val, err
		}
		val, found = t.find32(ip, mask)
	}

	var err error
	if !found {
		err = ErrNotFound
	}

	return val, err
}

func (t *Tree[T]) newNode6() (p *node6[T]) {
	if t.free6 != nil {
		p = t.free6
		t.free6 = t.free6.right
		*p = node6[T]{}
		return
	}

	ln := len(t.alloc6)
	if ln == cap(t.alloc6) {
		t.alloc6 = make([]node6[T], 0, ln+allocChunkGrowth)
		ln = 0
	}
	t.alloc6 = t.alloc6[:ln+1]

	return &(t.alloc6[ln])
}

func (t *Tree[T]) release6(n *node6[T]) {
	n.right = t.free6
	t.free6 = n
}

func (t *Tree[T]) releaseSubtree6(n *node6[T]) {
	if n == nil {
		return
	}
	t.releaseSubtree6(n.left)
	t.releaseSubtree6(n.right)
	t.release6(n)
}

func (t *Tree[T]) newNode4() (p *node4[T]) {
	if t.free4 != nil {
		p = t.free4
		t.free4 = t.free4.right
		*p = node4[T]{}
		return
	}

	ln := len(t.alloc4)
	if ln == cap(t.alloc4) {
		t.alloc4 = make([]node4[T], 0, ln+allocChunkGrowth)
		ln = 0
	}
	t.alloc4 = t.alloc4[:ln+1]

	return &(t.alloc4[ln])
}

func (t *Tree[T]) release4(n *node4[T]) {
	n.right = t.free4
	t.free4 = n
}

func (t *Tree[T]) releaseSubtree4(n *node4[T]) {
	if n == nil {
		return
	}
	t.releaseSubtree4(n.left)
	t.releaseSubtree4(n.right)
	t.release4(n)
}
