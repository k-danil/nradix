// Copyright (C) 2015 Alex Sergeyev
// This project is licensed under the terms of the MIT license.
// Read LICENSE file for information for all notices and permissions.

package nradix

import (
	"errors"
)

// Tree implements radix tree for working with IP/mask. Thread safety is not guaranteed, you should choose your own style of protecting safety of operations.
type Tree[T any] struct {
	root *node[T]
	free *node[T]

	alloc []node[T]
	ipv6  bool
}

const (
	uint32StartBit  uint32 = 1 << 31
	uint128StartBit uint64 = 1 << 63
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
	if preallocate > 0 {
		t.alloc = make([]node[T], 0, preallocate)
	}
	t.root = t.newNode()
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
	} else {
		ip, mask, err := parseCIDR4(cidr)
		if err != nil {
			return err
		}
		return t.insert32(ip, mask, val, overwrite)
	}
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
	} else {
		ip, mask, err := parseCIDR4(cidr)
		if err != nil {
			return err
		}
		return t.delete32(ip, mask, wholeRange)
	}
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
		ip, mask, err := parseCIDR4(cidr)
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

func (t *Tree[T]) newNode() (p *node[T]) {
	if t.free != nil {
		p = t.free
		t.free = t.free.right
		*p = node[T]{}
		return
	}

	ln := len(t.alloc)
	if ln == cap(t.alloc) {
		// filled one row, make bigger one
		t.alloc = make([]node[T], 0, ln+200) // 200, 600, 1400, 3000, 6200, 12600 ...
		ln = 0
	}
	t.alloc = t.alloc[:ln+1]

	return &(t.alloc[ln])
}
