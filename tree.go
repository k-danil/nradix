// Copyright (C) 2015 Alex Sergeyev
// This project is licensed under the terms of the MIT license.
// Read LICENSE file for information for all notices and permissions.

package nradix

import (
	"errors"
	"net/netip"
)

// Tree implements radix tree for working with IP/mask. Thread safety is not guaranteed, you should choose your own style of protecting safety of operations.
type Tree[T any] struct {
	v4 *tree4[T]
	v6 *tree6[T]
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

// NewTree4 creates a tree for IPv4 prefixes, reserving room for preallocate nodes.
func NewTree4[T any](preallocate int) (t *Tree[T]) {
	return &Tree[T]{v4: newTree4[T](preallocate)}
}

// NewTree6 creates a tree for IPv6 prefixes, reserving room for preallocate nodes.
// Bare IPv4 prefixes are accepted too and stored in their IPv4-mapped form.
func NewTree6[T any](preallocate int) (t *Tree[T]) {
	return &Tree[T]{v6: newTree6[T](preallocate)}
}

func (t *Tree[T]) AddCIDR(cidr string, val T) error {
	return t.setInternal(cidr, val, false)
}

func (t *Tree[T]) SetCIDR(cidr string, val T) error {
	return t.setInternal(cidr, val, true)
}

func (t *Tree[T]) setInternal(cidr string, val T, overwrite bool) error {
	if t.v6 != nil {
		ip, mask, err := parseCIDR6(cidr)
		if err != nil {
			return err
		}
		return t.v6.insert(ip, mask, val, overwrite)
	}

	ip, mask, err := parseCIDR4(stringToBytes(cidr))
	if err != nil {
		return err
	}
	return t.v4.insert(ip, mask, val, overwrite)
}

func (t *Tree[T]) DeleteWholeRangeCIDR(cidr string) error {
	return t.deleteInternal(cidr, true)
}

func (t *Tree[T]) DeleteCIDR(cidr string) error {
	return t.deleteInternal(cidr, false)
}

func (t *Tree[T]) deleteInternal(cidr string, wholeRange bool) error {
	if t.v6 != nil {
		ip, mask, err := parseCIDR6(cidr)
		if err != nil {
			return err
		}
		return t.v6.delete(ip, mask, wholeRange)
	}

	ip, mask, err := parseCIDR4(stringToBytes(cidr))
	if err != nil {
		return err
	}
	return t.v4.delete(ip, mask, wholeRange)
}

func (t *Tree[T]) FindCIDR(cidr string) (T, error) {
	var found bool
	var val T
	if t.v6 != nil {
		ip, mask, err := parseCIDR6(cidr)
		if err != nil {
			return val, err
		}
		val, found = t.v6.find(ip, mask)
	} else {
		ip, mask, err := parseCIDR4(stringToBytes(cidr))
		if err != nil {
			return val, err
		}
		val, found = t.v4.find(ip, mask)
	}

	var err error
	if !found {
		err = ErrNotFound
	}

	return val, err
}

// Find32 looks up an IPv4 host address. On an IPv6 tree the address is matched
// in its IPv4-mapped form, the same way FindCIDR treats a bare IPv4 string.
func (t *Tree[T]) Find32(ip uint32) (val T, err error) {
	var found bool
	if t.v6 != nil {
		val, found = t.v6.find(ip4To6(ip), fullMask128)
	} else {
		val, found = t.v4.find(ip, ipv4HostMask)
	}

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

	var found bool
	if t.v6 != nil {
		val, found = t.v6.find(addrTo128(addr), fullMask128)
	} else {
		ip, ok := addrTo32(addr)
		if !ok {
			err = ErrBadIP
			return
		}
		val, found = t.v4.find(ip, ipv4HostMask)
	}

	if !found {
		err = ErrNotFound
	}
	return
}
