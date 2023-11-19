package nradix

import (
	"encoding/binary"
	"net"
	"strings"
)

const ipv4HostMask = 0xffffffff

func loadIP4(ipStr string) (ip uint32, err error) {
	var (
		oct uint32
		num byte
	)

	for _, b := range []byte(ipStr) {
		if b == '.' {
			if oct > 255 {
				return 0, ErrBadIP
			}
			num++
			ip = ip<<8 + oct
			oct = 0
		} else {
			b -= '0'
			if b > 9 {
				return 0, ErrBadIP
			}
			oct = oct*10 + uint32(b)
		}
	}

	if oct > 255 || num != 3 {
		return 0, ErrBadIP
	}
	ip = ip<<8 + oct

	return
}

func parseCIDR4(cidr string) (ip, mask uint32, err error) {
	if p := strings.IndexByte(cidr, '/'); p > 0 {
		for _, c := range []byte(cidr[p+1:]) {
			c -= '0'
			if c > 9 {
				return 0, 0, ErrBadIP
			}
			mask = mask*10 + uint32(c)
		}
		if mask > 32 {
			return 0, 0, ErrBadIP
		}
		mask = ipv4HostMask << (32 - mask)
		cidr = cidr[:p]
	} else {
		mask = ipv4HostMask
	}
	ip, err = loadIP4(cidr)
	return
}

func parseCIDR6(cidr string) (ip, mask uint128, err error) {
	var maskLen uint32
	if p := strings.IndexByte(cidr, '/'); p > 0 {
		for _, c := range []byte(cidr[p+1:]) {
			c -= '0'
			if c > 9 {
				err = ErrBadIP
				return
			}
			maskLen = maskLen*10 + uint32(c)
		}
		if maskLen > 128 {
			err = ErrBadIP
			return
		}
		cidr = cidr[:p]
	} else {
		maskLen = 128
	}

	ipIp := net.ParseIP(cidr)
	if ipIp == nil {
		err = ErrBadIP
		return
	}

	if len(ipIp) == net.IPv4len {
		maskLen += 96
		if maskLen > 128 {
			err = ErrBadIP
			return
		}
		ipIp = ipIp.To16()
	}

	ip[0] = binary.BigEndian.Uint64(ipIp[:8])
	ip[1] = binary.BigEndian.Uint64(ipIp[8:])

	if maskLen > 64 {
		mask[0] = ^uint64(0)
		mask[1] = ^uint64(0) << (128 - maskLen)
	} else {
		mask[0] = ^uint64(0) << (64 - maskLen)
		mask[1] = 0
	}

	return
}
