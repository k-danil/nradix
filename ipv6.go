package nradix

func (t *Tree[T]) insert128(ip, mask uint128, val T, overwrite bool) (err error) {
	n := t.root
	ipHalf, maskHalf := ip.hi, mask.hi

	var second bool
SECOND:
	for bit := uint128StartBit; maskHalf&bit != 0; bit >>= 1 {
		var next *node[T]
		if next = n.getNext(ipHalf&bit != 0); next == nil {
			next = n.setNext(ipHalf&bit != 0, t.newNode())
			next.parent = n
		}
		n = next
	}
	if !second {
		ipHalf, maskHalf = ip.lo, mask.lo
		second = true
		goto SECOND
	}

	if n.set && !overwrite {
		return ErrNodeBusy
	}
	n.setValue(val)

	return
}

func (t *Tree[T]) delete128(ip, mask uint128, wholeRange bool) (err error) {
	n := t.root
	ipHalf, maskHalf := ip.hi, mask.hi

	var second bool
SECOND:
	for bit := uint128StartBit; maskHalf&bit != 0; bit >>= 1 {
		if n = n.getNext(ipHalf&bit != 0); n == nil {
			return ErrNotFound
		}
	}
	if !second {
		ipHalf, maskHalf = ip.lo, mask.lo
		second = true
		goto SECOND
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

func (t *Tree[T]) find128(ip, mask uint128) (val T, found bool) {
	n := t.root
	val, found = n.val, n.set
	ipHalf, maskHalf := ip.hi, mask.hi

	var second bool
SECOND:
	for bit := uint128StartBit; maskHalf&bit != 0; bit >>= 1 {
		if n = n.getNext(ipHalf&bit != 0); n == nil {
			return
		}
		if n.set {
			val, found = n.val, true
		}
	}
	if !second {
		ipHalf, maskHalf = ip.lo, mask.lo
		second = true
		goto SECOND
	}

	return
}
