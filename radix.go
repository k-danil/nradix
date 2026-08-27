package nradix

import "math/bits"

type tree[T any] struct {
	root  *node[T]
	free  *node[T]
	alloc []node[T]
}

func newTree[T any](preallocate int) (t *tree[T]) {
	t = &tree[T]{}
	if preallocate > 0 {
		t.alloc = make([]node[T], 0, preallocate)
	}
	t.root = t.newNode()
	return
}

func (t *tree[T]) newNode() (p *node[T]) {
	if t.free != nil {
		p = t.free
		t.free = p.right
		p.right = nil
		return
	}

	ln := len(t.alloc)
	if ln == cap(t.alloc) {
		t.alloc = make([]node[T], 0, ln+allocChunkGrowth)
		ln = 0
	}
	t.alloc = t.alloc[:ln+1]

	return &(t.alloc[ln])
}

// release clears the node so a freed prefix stops keeping its value alive;
// right doubles as the free-list link.
func countNodes[T any](n *node[T]) int {
	if n == nil {
		return 0
	}
	return 1 + countNodes(n.left) + countNodes(n.right)
}

// clone copies the subtree depth first, so a node and its descendants land in
// the arena next to each other.
func (t *tree[T]) clone(src *node[T]) (dst *node[T]) {
	if src == nil {
		return
	}
	dst = t.newNode()
	*dst = *src
	dst.left = t.clone(src.left)
	dst.right = t.clone(src.right)
	return
}

func (t *tree[T]) compact() {
	fresh := &tree[T]{alloc: make([]node[T], 0, countNodes(t.root))}
	fresh.root = fresh.clone(t.root)
	*t = *fresh
}

func (t *tree[T]) release(n *node[T]) {
	*n = node[T]{right: t.free}
	t.free = n
}

func (t *tree[T]) releaseSubtree(n *node[T]) {
	if n == nil {
		return
	}
	t.releaseSubtree(n.left)
	t.releaseSubtree(n.right)
	t.release(n)
}

func (t *tree[T]) insert(ip, mask uint128, val T, overwrite bool) (err error) {
	plen := plenOf128(mask)
	ip = and128(ip, mask)

	n := t.root
	for {
		if n.plen == plen {
			if n.set && !overwrite {
				return ErrNodeBusy
			}
			n.setValue(val)
			return
		}

		right := bit128(ip, n.plen)
		child := n.getNext(right)
		if child == nil {
			n.setNext(right, t.newLeaf(ip, plen, val))
			return
		}

		c := cpl128(child.prefix, ip)
		if child.plen <= plen && c >= child.plen {
			n = child
			continue
		}

		n.setNext(right, t.split(child, c, ip, plen, val))
		return
	}
}

func (t *tree[T]) newLeaf(ip uint128, plen uint8, val T) (leaf *node[T]) {
	leaf = t.newNode()
	leaf.prefix, leaf.plen = ip, plen
	leaf.setValue(val)
	return
}

func (t *tree[T]) split(child *node[T], c uint8, ip uint128, plen uint8, val T) (top *node[T]) {
	top = t.newLeaf(ip, plen, val)
	if c < plen {
		fork := t.newNode()
		fork.prefix, fork.plen = and128(ip, mask128(c)), c
		fork.setNext(bit128(ip, c), top)
		top = fork
	}
	top.setNext(bit128(child.prefix, top.plen), child)
	return
}

// findHost drops the checks that cannot fire when the query is a full /128.
// plen rides along from the parent's cplen mirror, so each level costs a single
// dependent load. At plen 128 the masked shift picks a garbage direction, which
// is safe: a /128 node cannot have children.
func (t *tree[T]) findHost(ip uint128) (val T, found bool) {
	n := t.root
	plen := uint8(0)
	for plen < ipv6HalfMaskLength {
		if bits.LeadingZeros64(n.prefix.hi^ip.hi) < int(plen) {
			return
		}
		if n.set {
			val, found = n.val, true
		}
		right := ip.hi&(uint128StartBit>>(plen&(ipv6HalfMaskLength-1))) != 0
		next := n.getNext(right)
		if next == nil {
			return
		}
		plen = n.nextPlen(right)
		n = next
	}
	for {
		if n.prefix.hi != ip.hi || bits.LeadingZeros64(n.prefix.lo^ip.lo) < int(plen-ipv6HalfMaskLength) {
			return
		}
		if n.set {
			val, found = n.val, true
		}
		right := ip.lo&(uint128StartBit>>((plen-ipv6HalfMaskLength)&(ipv6HalfMaskLength-1))) != 0
		next := n.getNext(right)
		if next == nil {
			return
		}
		plen = n.nextPlen(right)
		n = next
	}
}

func (t *tree[T]) find(ip, mask uint128) (val T, found bool) {
	if mask == fullMask128 {
		return t.findHost(ip)
	}

	qlen := plenOf128(mask)
	ip = and128(ip, mask)

	n := t.root
	plen := uint8(0)
	for plen < ipv6HalfMaskLength {
		if plen > qlen || bits.LeadingZeros64(n.prefix.hi^ip.hi) < int(plen) {
			return
		}
		if n.set {
			val, found = n.val, true
		}
		if plen == qlen {
			return
		}
		right := ip.hi&(uint128StartBit>>(plen&(ipv6HalfMaskLength-1))) != 0
		next := n.getNext(right)
		if next == nil {
			return
		}
		plen = n.nextPlen(right)
		n = next
	}
	for {
		if plen > qlen || n.prefix.hi != ip.hi ||
			bits.LeadingZeros64(n.prefix.lo^ip.lo) < int(plen-ipv6HalfMaskLength) {
			return
		}
		if n.set {
			val, found = n.val, true
		}
		if plen == qlen {
			return
		}
		right := ip.lo&(uint128StartBit>>((plen-ipv6HalfMaskLength)&(ipv6HalfMaskLength-1))) != 0
		next := n.getNext(right)
		if next == nil {
			return
		}
		plen = n.nextPlen(right)
		n = next
	}
}

func (t *tree[T]) delete(ip, mask uint128, wholeRange bool) (err error) {
	plen := plenOf128(mask)
	ip = and128(ip, mask)

	var parents [ipv6MaxMaskLength + 1]*node[T]
	depth := 0

	n := t.root
	for {
		if n == nil {
			return ErrNotFound
		}
		if cpl128(n.prefix, ip) < min(n.plen, plen) {
			return ErrNotFound
		}
		if n.plen >= plen {
			break
		}
		parents[depth] = n
		depth++
		n = n.getNext(bit128(ip, n.plen))
	}

	if wholeRange {
		if depth == 0 {
			if !n.set && n.left == nil && n.right == nil {
				return ErrNotFound
			}
			t.releaseSubtree(n.left)
			t.releaseSubtree(n.right)
			n.left, n.right = nil, nil
			n.unsetValue()
			return
		}
		parents[depth-1].setNext(bit128(n.prefix, parents[depth-1].plen), nil)
		t.releaseSubtree(n)
		t.collapse(parents[:depth])
		return
	}

	if n.plen != plen || !n.set {
		return ErrNotFound
	}
	n.unsetValue()

	if n.forks() || depth == 0 {
		return
	}
	parents[depth-1].setNext(bit128(n.prefix, parents[depth-1].plen), n.onlyChild())
	t.release(n)
	t.collapse(parents[:depth])
	return
}

func (t *tree[T]) collapse(parents []*node[T]) {
	for i := len(parents) - 1; i > 0; i-- {
		n := parents[i]
		if n.set || n.forks() {
			return
		}
		parents[i-1].setNext(bit128(n.prefix, parents[i-1].plen), n.onlyChild())
		t.release(n)
	}
}
