package nradix

import (
	"bytes"
	"encoding/binary"
	"net/netip"
)

const (
	ipv4MaxMaskLength  = 32
	ipv6HalfMaskLength = 64
	ipv6MaxMaskLength  = 128

	ipv4OctetMax = 255
	ipv4DotCount = 3

	maskDigitsMax = 3

	ipv4In6Prefix uint64 = 0xffff << 32
)

func addrTo128(addr netip.Addr) (ip uint128) {
	b := addr.As16()
	ip.hi = binary.BigEndian.Uint64(b[:8])
	ip.lo = binary.BigEndian.Uint64(b[8:])
	return
}

func ip4To6(ip uint32) uint128 {
	return uint128{lo: ipv4In6Prefix | uint64(ip)}
}

// maskSep finds the '/' without scanning the whole string: a mask is at most
// three digits, so it can only sit in the last few bytes.
func maskSep(cidr []byte) int {
	for i := len(cidr) - 2; i >= 0 && i >= len(cidr)-maskDigitsMax-1; i-- {
		if cidr[i] == '/' {
			return i
		}
	}
	return -1
}

func isBareIPv4(addr []byte) bool {
	return bytes.IndexByte(addr, ':') < 0
}

func loadIP4(ipStr []byte) (ip uint32, err error) {
	var (
		oct    uint32
		dots   byte
		digits byte
	)

	for _, b := range ipStr {
		if b == '.' {
			if digits == 0 {
				return 0, ErrBadIP
			}
			if dots++; dots > ipv4DotCount {
				return 0, ErrBadIP
			}
			ip = ip<<8 + oct
			oct, digits = 0, 0
			continue
		}
		if b -= '0'; b > 9 {
			return 0, ErrBadIP
		}
		if digits == 1 && oct == 0 {
			return 0, ErrBadIP
		}
		digits = 1
		if oct = oct*10 + uint32(b); oct > ipv4OctetMax {
			return 0, ErrBadIP
		}
	}

	if digits == 0 || dots != ipv4DotCount {
		return 0, ErrBadIP
	}
	ip = ip<<8 + oct

	return
}

func parseCIDR6(cidr []byte) (ip, mask uint128, err error) {
	var (
		bare    = isBareIPv4(cidr)
		maskLen uint32
		v4      uint32
	)
	mask = uint128{^uint64(0), ^uint64(0)}

	if p := maskSep(cidr); p > 0 {
		off := uint(p + 1)
		if off >= uint(len(cidr)) {
			goto ERROR
		}
		for _, c := range cidr[p+1:] {
			if c -= '0'; c > 9 {
				goto ERROR
			}
			if maskLen == 0 && c == 0 && len(cidr) > p+2 {
				goto ERROR
			}
			if maskLen = maskLen*10 + uint32(c); maskLen > ipv6MaxMaskLength {
				goto ERROR
			}
		}
		cidr = cidr[:p]

		if bare {
			// a bare IPv4 prefix always lands at /96 or deeper, so the high
			// half stays all ones and needs no shifting
			if maskLen > ipv4MaxMaskLength {
				goto ERROR
			}
			mask.lo <<= ipv4MaxMaskLength - maskLen
			if v4, err = loadIP4(cidr); err != nil {
				goto ERROR
			}
			return ip4To6(v4), mask, nil
		}
		if maskLen > ipv6MaxMaskLength {
			goto ERROR
		}
		if maskLen != ipv6MaxMaskLength {
			if maskLen <= ipv6HalfMaskLength {
				mask.hi <<= ipv6HalfMaskLength - maskLen
			}
			mask.lo <<= ipv6MaxMaskLength - maskLen
		}
	}

	if bare {
		if v4, err = loadIP4(cidr); err != nil {
			goto ERROR
		}
		return ip4To6(v4), mask, nil
	}

	if ip, err = parseAddr6(cidr); err != nil {
		goto ERROR
	}

	return

ERROR:
	return uint128{}, uint128{}, ErrBadIP
}
