package nradix

type tree6[T any] struct {
	root  *node6[T]
	free  *node6[T]
	alloc []node6[T]
}

func newTree6[T any](preallocate int) (t *tree6[T]) {
	t = &tree6[T]{}
	if preallocate > 0 {
		t.alloc = make([]node6[T], 0, preallocate)
	}
	t.root = t.newNode()
	return
}

func (t *tree6[T]) newNode() (p *node6[T]) {
	if t.free != nil {
		p = t.free
		t.free = t.free.right
		*p = node6[T]{}
		return
	}

	ln := len(t.alloc)
	if ln == cap(t.alloc) {
		t.alloc = make([]node6[T], 0, ln+allocChunkGrowth)
		ln = 0
	}
	t.alloc = t.alloc[:ln+1]

	return &(t.alloc[ln])
}

func (t *tree6[T]) release(n *node6[T]) {
	n.right = t.free
	t.free = n
}

func (t *tree6[T]) releaseSubtree(n *node6[T]) {
	if n == nil {
		return
	}
	t.releaseSubtree(n.left)
	t.releaseSubtree(n.right)
	t.release(n)
}

func (t *tree6[T]) insert(ip, mask uint128, val T, overwrite bool) (err error) {
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

func (t *tree6[T]) newLeaf(ip uint128, plen uint8, val T) (leaf *node6[T]) {
	leaf = t.newNode()
	leaf.prefix, leaf.plen = ip, plen
	leaf.setValue(val)
	return
}

func (t *tree6[T]) split(child *node6[T], c uint8, ip uint128, plen uint8, val T) (top *node6[T]) {
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

func (t *tree6[T]) find(ip, mask uint128) (val T, found bool) {
	plen := plenOf128(mask)
	ip = and128(ip, mask)

	for n := t.root; n != nil; n = n.getNext(bit128(ip, n.plen)) {
		if n.plen > plen || cpl128(n.prefix, ip) < n.plen {
			return
		}
		if n.set {
			val, found = n.val, true
		}
		if n.plen == plen {
			return
		}
	}
	return
}

func (t *tree6[T]) delete(ip, mask uint128, wholeRange bool) (err error) {
	plen := plenOf128(mask)
	ip = and128(ip, mask)

	var parents [ipv6MaxMaskLength + 1]*node6[T]
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

func (t *tree6[T]) collapse(parents []*node6[T]) {
	for i := len(parents) - 1; i > 0; i-- {
		n := parents[i]
		if n.set || n.forks() {
			return
		}
		parents[i-1].setNext(bit128(n.prefix, parents[i-1].plen), n.onlyChild())
		t.release(n)
	}
}
