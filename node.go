package nradix

import "unsafe"

const sizeOfUintPtr = uint8(unsafe.Sizeof(uintptr(0)))

func b2u(b bool) uint8 {
	if b {
		return 1
	}
	return 0
}
