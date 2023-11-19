package nradix

func (t *Tree[T]) insert32(ip, mask uint32, val T, overwrite bool) (err error) {
	n := t.root
	for bit := startBit; bit&mask != 0; bit >>= 1 {
		var next *node[T]
		if next = n.getNext(ip&bit != 0); next == nil {
			next = n.setNext(ip&bit != 0, t.newNode())
			next.parent = n
		}
		n = next
	}
	if n.set && !overwrite {
		return ErrNodeBusy
	}
	n.setValue(val)

	return
}

func (t *Tree[T]) delete32(ip, mask uint32, wholeRange bool) (err error) {
	n := t.root
	for bit := startBit; bit&mask != 0; bit >>= 1 {
		if n = n.getNext(ip&bit != 0); n == nil {
			return ErrNotFound
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

func (t *Tree[T]) find32(ip, mask uint32) (T, bool) {
	n := t.root
	val, found := n.val, n.set

	for bit := startBit; mask&bit != 0; bit >>= 1 {
		if n = n.getNext(ip&bit != 0); n == nil {
			return val, found
		}
		if n.set {
			val, found = n.val, true
		}
	}

	return val, found
}
