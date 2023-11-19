package nradix

type node[T any] struct {
	left, right, parent *node[T]
	val                 T
	set                 bool
}

func (n *node[T]) getNext(right bool) *node[T] {
	if right {
		return n.right
	}
	return n.left
}

func (n *node[T]) setNext(right bool, nn *node[T]) *node[T] {
	if right {
		n.right = nn
	} else {
		n.left = nn
	}
	return nn
}

func (n *node[T]) setValue(val T) {
	n.set = true
	n.val = val
}

func (n *node[T]) unsetValue() error {
	if !n.set {
		return ErrNotFound
	}

	var val T
	n.set = false
	n.val = val
	return nil
}

func (n *node[T]) isValuable() bool {
	return n.right != nil || n.left != nil || n.parent == nil
}
