package nradix

type node[T any] struct {
	left, right, parent *node[T]
	val                 T
	set                 bool
}

func (n *node[T]) getNext(right bool) *node[T] {
	if right {
		return n.right
	} else {
		return n.left
	}
}

func (n *node[T]) setNext(right bool, nn *node[T]) {
	if right {
		n.right = nn
	} else {
		n.left = nn
	}
}

func (n *node[T]) setValue(val T) {
	n.set = true
	n.val = val
}

func (n *node[T]) unsetValue() {
	var val T
	n.set = false
	n.val = val
}

func (n *node[T]) isValuable() bool {
	return n.right != nil || n.left != nil || n.set || n.parent == nil
}
