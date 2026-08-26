package nradix

import (
	"bytes"
	"unsafe"
)

const (
	hexGroups      = 8
	hexGroupDigits = 4
	hexGroupBits   = 16
)

const notHex = 0xff

var hexDigits = func() (t [256]byte) {
	for i := range t {
		t[i] = notHex
	}
	for c := byte('0'); c <= '9'; c++ {
		t[c] = c - '0'
	}
	for c := byte('a'); c <= 'f'; c++ {
		t[c] = c - 'a' + 10
	}
	for c := byte('A'); c <= 'F'; c++ {
		t[c] = c - 'A' + 10
	}
	return
}()

// parseAddr6 expects an IPv6 literal; a bare IPv4 address is not its business.
// at reads s[i] without a bounds check; every call site checks i < len(s) first.
func at(s []byte, i int) byte {
	return *(*byte)(unsafe.Add(unsafe.Pointer(unsafe.SliceData(s)), i))
}

func parseAddr6(s []byte) (ip uint128, err error) {
	var (
		groups   [hexGroups]uint16
		filled   int
		ellipsis = -1
		i        int
		group    uint32
		digits   int
		embedded []byte
		v4       uint32
	)

	if len(s) == 0 {
		goto ERROR
	}

	if s[0] == ':' {
		if len(s) < 2 || at(s, 1) != ':' {
			goto ERROR
		}
		i, ellipsis = 2, 0
		if len(s) == 2 {
			return
		}
	}

	for i < len(s) {
		if at(s, i) == '%' {
			if i == len(s)-1 {
				goto ERROR
			}
			break
		}

		group, digits = 0, 0
		for i < len(s) {
			d := hexDigits[at(s, i)]
			if d == notHex {
				break
			}
			if digits++; digits > hexGroupDigits {
				goto ERROR
			}
			group = group<<4 | uint32(d)
			i++
		}
		if digits == 0 {
			goto ERROR
		}

		if i < len(s) && at(s, i) == '.' {
			embedded = s[i-digits:]
			if z := bytes.IndexByte(embedded, '%'); z >= 0 {
				if z == len(embedded)-1 {
					goto ERROR
				}
				embedded = embedded[:z]
			}

			if v4, err = loadIP4(embedded); err != nil {
				goto ERROR
			}
			if filled+2 > hexGroups {
				goto ERROR
			}
			groups[filled] = uint16(v4 >> hexGroupBits)
			groups[filled+1] = uint16(v4)
			filled += 2
			i = len(s)
			break
		}

		if filled >= hexGroups {
			goto ERROR
		}
		groups[filled] = uint16(group)
		filled++

		if i == len(s) {
			break
		}
		if at(s, i) == '%' {
			if i == len(s)-1 {
				goto ERROR
			}
			break
		}
		if at(s, i) != ':' {
			goto ERROR
		}

		if i++; i == len(s) {
			goto ERROR
		}
		if at(s, i) == ':' {
			if ellipsis >= 0 {
				goto ERROR
			}
			ellipsis = filled
			if i++; i == len(s) {
				break
			}
		} else if at(s, i) == '%' {
			goto ERROR
		}
	}

	if ellipsis < 0 {
		if filled != hexGroups {
			goto ERROR
		}
	} else {
		if filled == hexGroups {
			goto ERROR
		}
		for j := 1; j <= filled-ellipsis; j++ {
			groups[hexGroups-j], groups[filled-j] = groups[filled-j], 0
		}
	}

	ip.hi = uint64(groups[0])<<(3*hexGroupBits) | uint64(groups[1])<<(2*hexGroupBits) |
		uint64(groups[2])<<hexGroupBits | uint64(groups[3])
	ip.lo = uint64(groups[4])<<(3*hexGroupBits) | uint64(groups[5])<<(2*hexGroupBits) |
		uint64(groups[6])<<hexGroupBits | uint64(groups[7])

	return

ERROR:
	return uint128{}, ErrBadIP
}
