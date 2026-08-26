package nradix

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"strings"
)

const (
	ipv4HostMask = 0xffffffff

	ipv4MaxMaskLength  = 32
	ipv6HalfMaskLength = 64
	ipv6MaxMaskLength  = 128

	ipv4OctetMax = 255
	ipv4DotCount = 3

	ipv4In6Prefix uint64 = 0xffff << 32
)

func addrTo128(addr netip.Addr) (ip uint128) {
	b := addr.As16()
	ip.hi = binary.BigEndian.Uint64(b[:8])
	ip.lo = binary.BigEndian.Uint64(b[8:])
	return
}

func addrTo32(addr netip.Addr) (ip uint32, ok bool) {
	if !addr.Is4() && !addr.Is4In6() {
		return
	}
	b := addr.As4()
	return binary.BigEndian.Uint32(b[:]), true
}

func ip4To6(ip uint32) uint128 {
	return uint128{lo: ipv4In6Prefix | uint64(ip)}
}

func isBareIPv4(addr string) bool {
	return strings.IndexByte(addr, ':') < 0
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

func parseCIDR4(cidr []byte) (ip, mask uint32, err error) {
	mask = ipv4HostMask

	if p := bytes.LastIndexByte(cidr, '/'); p > 0 {
		off := uint(p + 1)
		if off >= uint(len(cidr)) {
			return 0, 0, ErrBadIP
		}
		var m uint32
		for _, c := range cidr[p+1:] {
			if c -= '0'; c > 9 {
				return 0, 0, ErrBadIP
			}
			if m = m*10 + uint32(c); m > ipv4MaxMaskLength {
				return 0, 0, ErrBadIP
			}
		}
		mask <<= ipv4MaxMaskLength - m
		cidr = cidr[:p]
	}

	ip, err = loadIP4(cidr)
	return
}

func parseCIDR6(cidr string) (ip, mask uint128, err error) {
	var (
		bare    = isBareIPv4(cidr)
		maskLen uint32
		v4      uint32
	)
	mask = uint128{^uint64(0), ^uint64(0)}

	if p := strings.LastIndexByte(cidr, '/'); p > 0 {
		off := uint(p + 1)
		if off >= uint(len(cidr)) {
			goto ERROR
		}
		for _, c := range []byte(cidr[p+1:]) {
			if c -= '0'; c > 9 {
				goto ERROR
			}
			if maskLen = maskLen*10 + uint32(c); maskLen > ipv6MaxMaskLength {
				goto ERROR
			}
		}
		cidr = cidr[:p]

		if bare {
			maskLen += ipv6MaxMaskLength - ipv4MaxMaskLength
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
		if v4, err = loadIP4(stringToBytes(cidr)); err != nil {
			goto ERROR
		}
		return ip4To6(v4), mask, nil
	}

	if ip, err = parseAddr6(stringToBytes(cidr)); err != nil {
		goto ERROR
	}

	return

ERROR:
	return uint128{}, uint128{}, ErrBadIP
}
