package nradix

type tree4[T any] struct {
	root  *node4[T]
	free  *node4[T]
	alloc []node4[T]
}

func newTree4[T any](preallocate int) (t *tree4[T]) {
	t = &tree4[T]{}
	if preallocate > 0 {
		t.alloc = make([]node4[T], 0, preallocate)
	}
	t.root = t.newNode()
	return
}

func (t *tree4[T]) newNode() (p *node4[T]) {
	if t.free != nil {
		p = t.free
		t.free = p.right
		p.right = nil
		return
	}

	ln := len(t.alloc)
	if ln == cap(t.alloc) {
		t.alloc = make([]node4[T], 0, ln+allocChunkGrowth)
		ln = 0
	}
	t.alloc = t.alloc[:ln+1]

	return &(t.alloc[ln])
}

// release clears the node so a freed prefix stops keeping its value alive;
// right doubles as the free-list link.
func (t *tree4[T]) release(n *node4[T]) {
	*n = node4[T]{right: t.free}
	t.free = n
}

func (t *tree4[T]) releaseSubtree(n *node4[T]) {
	if n == nil {
		return
	}
	t.releaseSubtree(n.left)
	t.releaseSubtree(n.right)
	t.release(n)
}

func (t *tree4[T]) insert(ip, mask uint32, val T, overwrite bool) (err error) {
	plen := plenOf4(mask)
	ip &= mask

	n := t.root
	for {
		if n.plen == plen {
			if n.set && !overwrite {
				return ErrNodeBusy
			}
			n.setValue(val)
			return
		}

		right := bit4(ip, n.plen)
		child := n.getNext(right)
		if child == nil {
			n.setNext(right, t.newLeaf(ip, plen, val))
			return
		}

		c := cpl4(child.prefix, ip)
		if child.plen <= plen && c >= child.plen {
			n = child
			continue
		}

		n.setNext(right, t.split(child, c, ip, plen, val))
		return
	}
}

func (t *tree4[T]) newLeaf(ip uint32, plen uint8, val T) (leaf *node4[T]) {
	leaf = t.newNode()
	leaf.prefix, leaf.plen = ip, plen
	leaf.setValue(val)
	return
}

func (t *tree4[T]) split(child *node4[T], c uint8, ip uint32, plen uint8, val T) (top *node4[T]) {
	top = t.newLeaf(ip, plen, val)
	if c < plen {
		fork := t.newNode()
		fork.prefix, fork.plen = ip&mask4(c), c
		fork.setNext(bit4(ip, c), top)
		top = fork
	}
	top.setNext(bit4(child.prefix, top.plen), child)
	return
}

func (t *tree4[T]) find(ip, mask uint32) (val T, found bool) {
	plen := plenOf4(mask)
	ip &= mask

	for n := t.root; n != nil; n = n.getNext(bit4(ip, n.plen)) {
		if n.plen > plen || cpl4(n.prefix, ip) < n.plen {
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

func (t *tree4[T]) delete(ip, mask uint32, wholeRange bool) (err error) {
	plen := plenOf4(mask)
	ip &= mask

	var parents [ipv4MaxMaskLength + 1]*node4[T]
	depth := 0

	n := t.root
	for {
		if n == nil {
			return ErrNotFound
		}
		if cpl4(n.prefix, ip) < min(n.plen, plen) {
			return ErrNotFound
		}
		if n.plen >= plen {
			break
		}
		parents[depth] = n
		depth++
		n = n.getNext(bit4(ip, n.plen))
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
		parents[depth-1].setNext(bit4(n.prefix, parents[depth-1].plen), nil)
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
	parents[depth-1].setNext(bit4(n.prefix, parents[depth-1].plen), n.onlyChild())
	t.release(n)
	t.collapse(parents[:depth])
	return
}

func (t *tree4[T]) collapse(parents []*node4[T]) {
	for i := len(parents) - 1; i > 0; i-- {
		n := parents[i]
		if n.set || n.forks() {
			return
		}
		parents[i-1].setNext(bit4(n.prefix, parents[i-1].plen), n.onlyChild())
		t.release(n)
	}
}
