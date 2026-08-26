package nradix

func (t *Tree[T]) insert32(ip, mask uint32, val T, overwrite bool) (err error) {
	plen := plenOf4(mask)
	ip &= mask

	n := t.root4
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
			n.setNext(right, t.newLeaf4(ip, plen, val))
			return
		}

		c := cpl4(child.prefix, ip)
		if child.plen <= plen && c >= child.plen {
			n = child
			continue
		}

		n.setNext(right, t.split4(child, c, ip, plen, val))
		return
	}
}

func (t *Tree[T]) newLeaf4(ip uint32, plen uint8, val T) (leaf *node4[T]) {
	leaf = t.newNode4()
	leaf.prefix, leaf.plen = ip, plen
	leaf.setValue(val)
	return
}

func (t *Tree[T]) split4(child *node4[T], c uint8, ip uint32, plen uint8, val T) (top *node4[T]) {
	top = t.newLeaf4(ip, plen, val)
	if c < plen {
		fork := t.newNode4()
		fork.prefix, fork.plen = ip&mask4(c), c
		fork.setNext(bit4(ip, c), top)
		top = fork
	}
	top.setNext(bit4(child.prefix, top.plen), child)
	return
}

func (t *Tree[T]) find32(ip, mask uint32) (val T, found bool) {
	plen := plenOf4(mask)
	ip &= mask

	for n := t.root4; n != nil; n = n.getNext(bit4(ip, n.plen)) {
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

func (t *Tree[T]) delete32(ip, mask uint32, wholeRange bool) (err error) {
	plen := plenOf4(mask)
	ip &= mask

	var parents [ipv4MaxMaskLength + 1]*node4[T]
	depth := 0

	n := t.root4
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
			t.releaseSubtree4(n.left)
			t.releaseSubtree4(n.right)
			n.left, n.right = nil, nil
			n.unsetValue()
			return
		}
		parents[depth-1].setNext(bit4(n.prefix, parents[depth-1].plen), nil)
		t.releaseSubtree4(n)
		t.collapse4(parents[:depth])
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
	t.release4(n)
	t.collapse4(parents[:depth])
	return
}

func (t *Tree[T]) collapse4(parents []*node4[T]) {
	for i := len(parents) - 1; i > 0; i-- {
		n := parents[i]
		if n.set || n.forks() {
			return
		}
		parents[i-1].setNext(bit4(n.prefix, parents[i-1].plen), n.onlyChild())
		t.release4(n)
	}
}
