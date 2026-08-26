package nradix

func (t *Tree[T]) insert128(ip, mask uint128, val T, overwrite bool) (err error) {
	plen := plenOf128(mask)
	ip = and128(ip, mask)

	n := t.root6
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
			n.setNext(right, t.newLeaf6(ip, plen, val))
			return
		}

		c := cpl128(child.prefix, ip)
		if child.plen <= plen && c >= child.plen {
			n = child
			continue
		}

		n.setNext(right, t.split6(child, c, ip, plen, val))
		return
	}
}

func (t *Tree[T]) newLeaf6(ip uint128, plen uint8, val T) (leaf *node6[T]) {
	leaf = t.newNode6()
	leaf.prefix, leaf.plen = ip, plen
	leaf.setValue(val)
	return
}

func (t *Tree[T]) split6(child *node6[T], c uint8, ip uint128, plen uint8, val T) (top *node6[T]) {
	top = t.newLeaf6(ip, plen, val)
	if c < plen {
		fork := t.newNode6()
		fork.prefix, fork.plen = and128(ip, mask128(c)), c
		fork.setNext(bit128(ip, c), top)
		top = fork
	}
	top.setNext(bit128(child.prefix, top.plen), child)
	return
}

func (t *Tree[T]) find128(ip, mask uint128) (val T, found bool) {
	plen := plenOf128(mask)
	ip = and128(ip, mask)

	for n := t.root6; n != nil; n = n.getNext(bit128(ip, n.plen)) {
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

func (t *Tree[T]) delete128(ip, mask uint128, wholeRange bool) (err error) {
	plen := plenOf128(mask)
	ip = and128(ip, mask)

	var parents [ipv6MaxMaskLength + 1]*node6[T]
	depth := 0

	n := t.root6
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
			t.releaseSubtree6(n.left)
			t.releaseSubtree6(n.right)
			n.left, n.right = nil, nil
			n.unsetValue()
			return
		}
		parents[depth-1].setNext(bit128(n.prefix, parents[depth-1].plen), nil)
		t.releaseSubtree6(n)
		t.collapse6(parents[:depth])
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
	t.release6(n)
	t.collapse6(parents[:depth])
	return
}

func (t *Tree[T]) collapse6(parents []*node6[T]) {
	for i := len(parents) - 1; i > 0; i-- {
		n := parents[i]
		if n.set || n.forks() {
			return
		}
		parents[i-1].setNext(bit128(n.prefix, parents[i-1].plen), n.onlyChild())
		t.release6(n)
	}
}
