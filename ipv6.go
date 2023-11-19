package nradix

func (t *Tree[T]) insert128(ip, mask uint128, val T, overwrite bool) (err error) {
	n := t.root
	for i := 0; i < len(mask); i++ {
		for bit := uint128StartBit; mask[i]&bit != 0; bit >>= 1 {
			var next *node[T]
			if next = n.getNext(ip[i]&bit != 0); next == nil {
				next = n.setNext(ip[i]&bit != 0, t.newNode())
				next.parent = n
			}
			n = next
		}
	}
	if n.set && !overwrite {
		return ErrNodeBusy
	}
	n.setValue(val)

	return
}

func (t *Tree[T]) delete128(ip, mask uint128, wholeRange bool) (err error) {
	n := t.root
	for i := 0; i < len(mask); i++ {
		for bit := uint128StartBit; mask[i]&bit != 0; bit >>= 1 {
			if n = n.getNext(ip[i]&bit != 0); n == nil {
				return ErrNotFound
			}
		}
	}

	if (!wholeRange && n.isValuable()) || n.parent == nil {
		return n.unsetValue()
	}

	// TODO Clear leaf downward
	for {
		n.parent.setNext(n.parent.right == n, nil)
		n.right = t.free
		t.free = n

		n = n.parent
		if n.isValuable() || n.set {
			return
		}
	}
}

func (t *Tree[T]) find128(ip, mask uint128) (T, bool) {
	n := t.root
	val, found := n.val, n.set

	for i := 0; i < len(mask); i++ {
		for bit := uint128StartBit; mask[i]&bit != 0; bit >>= 1 {
			if n = n.getNext(ip[i]&bit != 0); n == nil {
				return val, found
			}
			if n.set {
				val, found = n.val, true
			}
		}
	}

	return val, found
}
