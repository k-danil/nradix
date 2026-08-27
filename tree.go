// Copyright (C) 2015 Alex Sergeyev
// This project is licensed under the terms of the MIT license.
// Read LICENSE file for information for all notices and permissions.

package nradix

import (
	"errors"
	"net/netip"
)

// Tree implements radix tree for working with IP/mask. Thread safety is not guaranteed, you should choose your own style of protecting safety of operations.
// Tree implements radix tree for working with IP/mask. Thread safety is not guaranteed, you should choose your own style of protecting safety of operations.
type Tree[T any] struct {
	t *tree[T]
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

// NewTree creates a tree, reserving room for preallocate nodes. It holds IPv4
// and IPv6 prefixes alike: IPv4 ones are stored in their IPv4-mapped form, so
// "1.2.3.0/24" and "::ffff:1.2.3.0/120" name the same entry.
func NewTree[T any](preallocate int) (t *Tree[T]) {
	return &Tree[T]{t: newTree[T](preallocate)}
}

func (t *Tree[T]) AddCIDR(cidr string, val T) error {
	return t.setInternal(stringToBytes(cidr), val, false)
}

// AddCIDRBytes is AddCIDR for a prefix that is already bytes, saving the
// conversion a string would cost.
func (t *Tree[T]) AddCIDRBytes(cidr []byte, val T) error {
	return t.setInternal(cidr, val, false)
}

func (t *Tree[T]) SetCIDR(cidr string, val T) error {
	return t.setInternal(stringToBytes(cidr), val, true)
}

// SetCIDRBytes is SetCIDR for a prefix that is already bytes.
func (t *Tree[T]) SetCIDRBytes(cidr []byte, val T) error {
	return t.setInternal(cidr, val, true)
}

func (t *Tree[T]) setInternal(cidr []byte, val T, overwrite bool) error {
	ip, mask, err := parseCIDR6(cidr)
	if err != nil {
		return err
	}
	return t.t.insert(ip, mask, val, overwrite)
}

func (t *Tree[T]) DeleteWholeRangeCIDR(cidr string) error {
	return t.deleteInternal(stringToBytes(cidr), true)
}

// DeleteWholeRangeCIDRBytes is DeleteWholeRangeCIDR for a prefix that is
// already bytes.
func (t *Tree[T]) DeleteWholeRangeCIDRBytes(cidr []byte) error {
	return t.deleteInternal(cidr, true)
}

func (t *Tree[T]) DeleteCIDR(cidr string) error {
	return t.deleteInternal(stringToBytes(cidr), false)
}

// DeleteCIDRBytes is DeleteCIDR for a prefix that is already bytes.
func (t *Tree[T]) DeleteCIDRBytes(cidr []byte) error {
	return t.deleteInternal(cidr, false)
}

func (t *Tree[T]) deleteInternal(cidr []byte, wholeRange bool) error {
	ip, mask, err := parseCIDR6(cidr)
	if err != nil {
		return err
	}
	return t.t.delete(ip, mask, wholeRange)
}

func (t *Tree[T]) FindCIDR(cidr string) (val T, err error) {
	return t.FindCIDRBytes(stringToBytes(cidr))
}

// FindCIDRBytes is FindCIDR for a prefix that is already bytes.
func (t *Tree[T]) FindCIDRBytes(cidr []byte) (val T, err error) {
	ip, mask, err := parseCIDR6(cidr)
	if err != nil {
		return val, err
	}

	var found bool
	if val, found = t.t.find(ip, mask); !found {
		err = ErrNotFound
	}
	return
}

// Compact rebuilds the tree in a fresh arena, laying every node next to its
// descendants. Lookups walk top down, so this speeds them up markedly on large
// trees; it also reclaims the space left behind by deletions. Worth calling
// once after a table is loaded, and pointless on a tree that keeps changing.
func (t *Tree[T]) Compact() {
	t.t.compact()
}

// Find32 looks up an IPv4 host address. On an IPv6 tree the address is matched
// in its IPv4-mapped form, the same way FindCIDR treats a bare IPv4 string.
func (t *Tree[T]) Find32(ip uint32) (val T, err error) {
	val, found := t.t.find(ip4To6(ip), fullMask128)

	if !found {
		err = ErrNotFound
	}
	return
}

// FindAddr looks up a host address. An IPv4 tree accepts IPv4 and IPv4-mapped
// addresses only and reports ErrBadIP for anything else.
func (t *Tree[T]) FindAddr(addr netip.Addr) (val T, err error) {
	if !addr.IsValid() {
		err = ErrBadIP
		return
	}

	val, found := t.t.find(addrTo128(addr), fullMask128)

	if !found {
		err = ErrNotFound
	}
	return
}
