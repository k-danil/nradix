// Copyright (C) 2015 Alex Sergeyev
// This project is licensed under the terms of the MIT license.
// Read LICENSE file for information for all notices and permissions.

package nradix

import (
	"bytes"
	"errors"
	"net"
)

// Tree implements radix tree for working with IP/mask. Thread safety is not guaranteed, you should choose your own style of protecting safety of operations.
type Tree[T any] struct {
	root *node[T]
	free *node[T]

	alloc []node[T]
}

const (
	startBit  = uint32(0x80000000)
	startByte = byte(0x80)
)

var (
	ErrNodeBusy = errors.New("node busy")
	ErrNotFound = errors.New("no such node")
	ErrBadIP    = errors.New("bad IP address or mask")
)

// NewTree creates Tree.
func NewTree[T any]() (t *Tree[T]) {
	t = new(Tree[T])
	t.root = t.newNode()
	return
}

// AddCIDR adds value associated with IP/mask to the tree. Will return error for invalid CIDR or if value already exists.
func (t *Tree[T]) AddCIDR(cidr string, val T) error {
	return t.AddCIDRb([]byte(cidr), val)
}

func (t *Tree[T]) AddCIDRb(cidr []byte, val T) error {
	if bytes.IndexByte(cidr, '.') > 0 {
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
	return t.insert(ip, mask, val, false)
}

// SetCIDR set value associated with IP/mask to the tree. Will return error for invalid CIDR.
func (t *Tree[T]) SetCIDR(cidr string, val T) error {
	return t.SetCIDRb([]byte(cidr), val)
}

func (t *Tree[T]) SetCIDRb(cidr []byte, val T) error {
	if bytes.IndexByte(cidr, '.') > 0 {
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
	return t.insert(ip, mask, val, true)
}

// DeleteWholeRangeCIDR removes all values associated with IPs
// in the entire subnet specified by the CIDR.
func (t *Tree[T]) DeleteWholeRangeCIDR(cidr string) error {
	return t.DeleteWholeRangeCIDRb([]byte(cidr))
}

func (t *Tree[T]) DeleteWholeRangeCIDRb(cidr []byte) error {
	if bytes.IndexByte(cidr, '.') > 0 {
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
	return t.delete(ip, mask, true)
}

// DeleteCIDR removes value associated with IP/mask from the tree.
func (t *Tree[T]) DeleteCIDR(cidr string) error {
	return t.DeleteCIDRb([]byte(cidr))
}

func (t *Tree[T]) DeleteCIDRb(cidr []byte) error {
	if bytes.IndexByte(cidr, '.') > 0 {
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
	return t.delete(ip, mask, false)
}

// FindCIDR traverses tree to proper Node and returns previously saved information in longest covered IP.
func (t *Tree[T]) FindCIDR(cidr string) (T, error) {
	return t.FindCIDRb([]byte(cidr))
}

func (t *Tree[T]) FindCIDRb(cidr []byte) (val T, err error) {
	if bytes.IndexByte(cidr, '.') > 0 {
		var ip, mask uint32
		if ip, mask, err = parseCIDR4(cidr); err != nil {
			return
		}
		return t.find32(ip, mask)
	}
	var ip net.IP
	var mask net.IPMask
	if ip, mask, err = parseCIDR6(cidr); err != nil || ip == nil {
		if ip == nil {
			err = ErrBadIP
		}
		return
	}
	return t.find(ip, mask)
}

func (t *Tree[T]) insert32(ip, mask uint32, val T, overwrite bool) (err error) {
	bit := startBit
	n := t.root
	next := t.root
	for bit&mask != 0 {
		if next = n.getNext(ip&bit != 0); next == nil {
			break
		}
		bit >>= 1
		n = next
	}
	if next != nil {
		if n.set && !overwrite {
			err = ErrNodeBusy
		} else {
			n.setValue(val)
		}
		return
	}
	for bit&mask != 0 {
		next = t.newNode()
		next.parent = n
		n.setNext(ip&bit != 0, next)
		bit >>= 1
		n = next
	}
	n.setValue(val)

	return
}

func (t *Tree[T]) insert(ip net.IP, mask net.IPMask, val T, overwrite bool) (err error) {
	if len(ip) != len(mask) {
		err = ErrBadIP
		return
	}

	var i int
	bit := startByte
	n := t.root
	next := t.root
	for bit&mask[i] != 0 {
		if next = n.getNext(ip[i]&bit != 0); next == nil {
			break
		}
		n = next
		if bit >>= 1; bit == 0 {
			if i++; i == len(ip) {
				break
			}
			bit = startByte
		}

	}
	if next != nil {
		if n.set && !overwrite {
			err = ErrNodeBusy
		} else {
			n.setValue(val)
		}
		return
	}
	for bit&mask[i] != 0 {
		next = t.newNode()
		next.parent = n
		n.setNext(ip[i]&bit != 0, next)
		n = next
		if bit >>= 1; bit == 0 {
			if i++; i == len(ip) {
				break
			}
			bit = startByte
		}
	}
	n.setValue(val)

	return
}

func (t *Tree[T]) delete32(ip, mask uint32, wholeRange bool) (err error) {
	bit := startBit
	n := t.root
	for n != nil && bit&mask != 0 {
		n = n.getNext(ip&bit != 0)
		bit >>= 1
	}
	if n == nil {
		err = ErrNotFound
		return
	}

	if !wholeRange && (n.right != nil || n.left != nil) {
		// keep it just trim val
		if n.set {
			n.unsetValue()
		} else {
			err = ErrNotFound
		}
		return
	}

	// need to trim leaf
	for {
		n.parent.setNext(n.parent.right == n, nil)
		// reserve this node[T] for future use
		n.right = t.free
		t.free = n

		n = n.parent
		if n.isValuable() {
			break
		}
	}

	return
}

func (t *Tree[T]) delete(ip net.IP, mask net.IPMask, wholeRange bool) (err error) {
	if len(ip) != len(mask) {
		err = ErrBadIP
		return
	}

	var i int
	bit := startByte
	n := t.root
	for n != nil && bit&mask[i] != 0 {
		n = n.getNext(ip[i]&bit != 0)
		if bit >>= 1; bit == 0 {
			if i++; i == len(ip) {
				break
			}
			bit = startByte
		}
	}
	if n == nil {
		err = ErrNotFound
		return
	}

	if !wholeRange && (n.right != nil || n.left != nil) {
		// keep it just trim val
		if n.set {
			n.unsetValue()
		} else {
			err = ErrNotFound
		}
		return
	}

	// need to trim leaf
	for {
		n.parent.setNext(n.parent.right == n, nil)
		// reserve this node[T] for future use
		n.right = t.free
		t.free = n

		n = n.parent
		if n.isValuable() {
			break
		}
	}

	return
}

func (t *Tree[T]) find32(ip, mask uint32) (val T, err error) {
	bit := startBit
	n := t.root

	var found bool
	for n != nil {
		if found = n.set; found {
			val = n.val
		}
		n = n.getNext(ip&bit != 0)
		if mask&bit == 0 {
			break
		}
		bit >>= 1
	}

	if !found {
		err = ErrNotFound
	}

	return
}

func (t *Tree[T]) find(ip net.IP, mask net.IPMask) (val T, err error) {
	if len(ip) != len(mask) {
		err = ErrBadIP
		return
	}
	var i int
	bit := startByte
	n := t.root

	var found bool
	for n != nil {
		if found = n.set; found {
			val = n.val
		}
		n = n.getNext(ip[i]&bit != 0)
		if mask[i]&bit == 0 {
			break
		}
		if bit >>= 1; bit == 0 {
			i, bit = i+1, startByte
			if i >= len(ip) {
				// reached depth of the tree, there should be matching node[T]...
				if found = n != nil && n.set; found {
					val = n.val
				}
				break
			}
		}
	}

	if !found {
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
		t.alloc = make([]node[T], 1, ln+200) // 200, 600, 1400, 3000, 6200, 12600 ...
		ln = 0
	} else {
		t.alloc = t.alloc[:ln+1]
	}
	p = &(t.alloc[ln])

	return
}
