package nradix

import "unsafe"

type node[T any] struct {
	left, right, parent *node[T]
	val                 T
	set                 bool
}

func b2u(b bool) uint8 {
	if b {
		return 1
	}
	return 0
}

const sizeOfUintPtr = uint8(unsafe.Sizeof(uintptr(0)))

func (n *node[T]) getNext(right bool) *node[T] {
	return *(**node[T])(unsafe.Add(unsafe.Pointer(n), b2u(right)*sizeOfUintPtr))
}

func (n *node[T]) setNext(right bool, nn *node[T]) *node[T] {
	*(**node[T])(unsafe.Add(unsafe.Pointer(n), b2u(right)*sizeOfUintPtr)) = nn
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
