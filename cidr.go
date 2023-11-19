package nradix

import (
	"bytes"
	"net"
)

const ipv4HostMask = 0xffffffff

var (
	ipv6HostMask = net.IPMask{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
)

func loadIP4(ipStr []byte) (ip uint32, err error) {
	var (
		oct    uint32
		b, num byte
	)

	for _, b = range ipStr {
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

func parseCIDR4(cidr []byte) (ip, mask uint32, err error) {
	if p := bytes.IndexByte(cidr, '/'); p > 0 {
		for _, c := range cidr[p+1:] {
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

func parseCIDR6(cidr []byte) (ip net.IP, mask net.IPMask, err error) {
	if p := bytes.IndexByte(cidr, '/'); p > 0 {
		var ipm *net.IPNet
		if _, ipm, err = net.ParseCIDR(string(cidr)); err != nil {
			return
		}
		ip, mask = ipm.IP.To16(), ipm.Mask
		if len(mask) == net.IPv4len {
			mask = append(ipv6HostMask[:12], mask...)
		}
	} else {
		if ip = net.ParseIP(string(cidr)); ip == nil {
			err = ErrBadIP
			return
		}
		ip = ip.To16()
		mask = ipv6HostMask
	}

	return
}
