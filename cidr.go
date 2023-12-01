package nradix

import (
	"net/netip"
	"strings"
	"unsafe"
)

const (
	ipv4HostMask = 0xffffffff

	ipv4MaxMaskLength  = 32
	ipv6HalfMaskLength = 64
	ipv6MaxMaskLength  = 128
)

func loadIP4(ipStr string) (ip uint32, err error) {
	var (
		oct uint32
		num byte
	)

	for _, b := range []byte(ipStr) {
		if b == '.' {
			if oct > 255 {
				goto ERROR
			}
			num++
			ip = ip<<8 + oct
			oct = 0
			continue
		}
		if b -= '0'; b > 9 {
			goto ERROR
		}
		oct = oct*10 + uint32(b)
	}

	if oct > 255 || num != 3 {
		goto ERROR
	}
	ip = ip<<8 + oct

	return

ERROR:
	return 0, ErrBadIP
}

func parseCIDR4(cidr string) (ip, mask uint32, err error) {
	mask = ipv4HostMask
	if p := strings.LastIndexByte(cidr, '/'); p > 0 {
		off := uint(p + 1)
		if off >= uint(len(cidr)) {
			goto ERROR
		}
		var m uint32
		for _, c := range []byte(cidr[p+1:]) {
			if c -= '0'; c > 9 {
				goto ERROR
			}
			m = m*10 + uint32(c)
		}

		if m > ipv4MaxMaskLength {
			goto ERROR
		}
		mask <<= ipv4MaxMaskLength - m
		cidr = cidr[:p]
	}
	ip, err = loadIP4(cidr)
	return

ERROR:
	return 0, 0, ErrBadIP
}

func parseCIDR6(cidr string) (ip, mask uint128, err error) {
	var ipIp netip.Addr
	mask = uint128{^uint64(0), ^uint64(0)}

	if p := strings.LastIndexByte(cidr, '/'); p > 0 {
		var maskLen uint32
		off := uint(p + 1)
		if off >= uint(len(cidr)) {
			goto ERROR
		}
		for _, c := range []byte(cidr[p+1:]) {
			if c -= '0'; c > 9 {
				goto ERROR
			}
			maskLen = maskLen*10 + uint32(c)
		}
		cidr = cidr[:p]

		if strings.LastIndexByte(cidr, '.') > 0 {
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

	if ipIp, err = netip.ParseAddr(cidr); err != nil {
		goto ERROR
	}
	ip = *(*uint128)(unsafe.Pointer(&ipIp))

	return

ERROR:
	return uint128{}, uint128{}, ErrBadIP
}
