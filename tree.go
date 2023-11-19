// Copyright (C) 2015 Alex Sergeyev
// This project is licensed under the terms of the MIT license.
// Read LICENSE file for information for all notices and permissions.

package nradix

import (
	"errors"
	"net"
)

// Tree implements radix tree for working with IP/mask. Thread safety is not guaranteed, you should choose your own style of protecting safety of operations.
type Tree[T any] struct {
	root *node[T]
	free *node[T]

	alloc []node[T]
	ipv6  bool
}

const (
	startBit  uint32 = 1 << 31
	startByte byte   = 1 << 7
)

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

// AddCIDR adds value associated with IP/mask to the tree. Will return error for invalid CIDR or if value already exists.
func (t *Tree[T]) AddCIDR(cidr string, val T) error {
	return t.AddCIDRb([]byte(cidr), val)
}

func (t *Tree[T]) AddCIDRb(cidr []byte, val T) error {
	if !t.ipv6 {
		ip, mask, err := parseCIDR4(cidr)
		if err != nil {
			return err
		}
		return t.insert32(ip, mask, val, false)
	}
	ip, mask, err := parseCIDR6(cidr)
	if err != nil {
		return err
	}
	return t.insert128(ip, mask, val, false)
}

// SetCIDR set value associated with IP/mask to the tree. Will return error for invalid CIDR.
func (t *Tree[T]) SetCIDR(cidr string, val T) error {
	return t.SetCIDRb([]byte(cidr), val)
}

func (t *Tree[T]) SetCIDRb(cidr []byte, val T) error {
	if !t.ipv6 {
		ip, mask, err := parseCIDR4(cidr)
		if err != nil {
			return err
		}
		return t.insert32(ip, mask, val, true)
	}
	ip, mask, err := parseCIDR6(cidr)
	if err != nil {
		return err
	}
	return t.insert128(ip, mask, val, true)
}

// DeleteWholeRangeCIDR removes all values associated with IPs
// in the entire subnet specified by the CIDR.
func (t *Tree[T]) DeleteWholeRangeCIDR(cidr string) error {
	return t.DeleteWholeRangeCIDRb([]byte(cidr))
}

func (t *Tree[T]) DeleteWholeRangeCIDRb(cidr []byte) error {
	if !t.ipv6 {
		ip, mask, err := parseCIDR4(cidr)
		if err != nil {
			return err
		}
		return t.delete32(ip, mask, true)
	}
	ip, mask, err := parseCIDR6(cidr)
	if err != nil {
		return err
	}
	return t.delete128(ip, mask, true)
}

// DeleteCIDR removes value associated with IP/mask from the tree.
func (t *Tree[T]) DeleteCIDR(cidr string) error {
	return t.DeleteCIDRb([]byte(cidr))
}

func (t *Tree[T]) DeleteCIDRb(cidr []byte) error {
	if !t.ipv6 {
		ip, mask, err := parseCIDR4(cidr)
		if err != nil {
			return err
		}
		return t.delete32(ip, mask, false)
	}
	ip, mask, err := parseCIDR6(cidr)
	if err != nil {
		return err
	}
	return t.delete128(ip, mask, false)
}

// FindCIDR traverses tree to proper Node and returns previously saved information in longest covered IP.
func (t *Tree[T]) FindCIDR(cidr string) (T, error) {
	return t.FindCIDRb([]byte(cidr))
}

func (t *Tree[T]) FindCIDRb(cidr []byte) (val T, err error) {
	var found bool
	if !t.ipv6 {
		var ip, mask uint32
		if ip, mask, err = parseCIDR4(cidr); err != nil {
			return
		}
		if val, found = t.find32(ip, mask); !found {
			err = ErrNotFound
		}
		return
	}
	var ip net.IP
	var mask net.IPMask
	if ip, mask, err = parseCIDR6(cidr); err != nil {
		return
	}
	if val, found = t.find128(ip, mask); !found {
		err = ErrNotFound
	}
	return
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
