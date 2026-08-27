package nradix

import (
	"math/bits"
	"net/netip"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func mask128Of(prefixLen int) (mask uint128) {
	for i := range prefixLen {
		if i < ipv6HalfMaskLength {
			mask.hi |= uint128StartBit >> i
		} else {
			mask.lo |= uint128StartBit >> (i - ipv6HalfMaskLength)
		}
	}
	return
}

func TestParseBareIPv4(t *testing.T) {
	tests := []struct {
		cidr    string
		wantIP  uint32
		wantLen int
		wantErr bool
	}{
		{cidr: "1.2.3.4", wantIP: 0x01020304, wantLen: ipv4MaxMaskLength},
		{cidr: "1.2.3.4/24", wantIP: 0x01020304, wantLen: 24},
		{cidr: "1.2.3.4/032", wantErr: true}, // netip rejects a padded mask too
		{cidr: "0.0.0.0/0", wantLen: 0},
		{cidr: "255.255.255.255/32", wantIP: 0xffffffff, wantLen: 32},

		{cidr: "1.2.3.4/33", wantErr: true},
		{cidr: "1.2.3.4/4294967328", wantErr: true}, // 2^32+32: wraps to a valid length
		{cidr: "1.2.3.4/99999999999999999999", wantErr: true},
		{cidr: "1.2.3.4/", wantErr: true},

		{cidr: "1..3.4", wantErr: true},
		{cidr: ".1.2.3", wantErr: true},
		{cidr: "1.2.3.", wantErr: true},
		{cidr: "...", wantErr: true},
		{cidr: "1.2.3", wantErr: true},
		{cidr: "", wantErr: true},

		{cidr: "1.2.3.010", wantErr: true},
		{cidr: "01.2.3.4", wantErr: true},
		{cidr: "1.2.3.00", wantErr: true},
		{cidr: "0.0.0.0", wantIP: 0, wantLen: ipv4MaxMaskLength},

		{cidr: "1.2.3.256", wantErr: true},
		{cidr: "1.2.3.4294967296", wantErr: true}, // 2^32: wraps to 0
	}

	for _, tt := range tests {
		t.Run(tt.cidr, func(t *testing.T) {
			ip, mask, err := parseCIDR6(stringToBytes(tt.cidr))
			if tt.wantErr {
				require.ErrorIs(t, err, ErrBadIP)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, ip4To6(tt.wantIP), ip)
			assert.Equal(t, mask128Of(tt.wantLen+ipv6MaxMaskLength-ipv4MaxMaskLength), mask)
		})
	}
}

func TestParseCIDR6(t *testing.T) {
	tests := []struct {
		cidr    string
		wantHi  uint64
		wantLo  uint64
		wantLen int
		wantErr bool
	}{
		{cidr: "dead::", wantHi: 0xdead000000000000, wantLen: ipv6MaxMaskLength},
		{cidr: "dead::/16", wantHi: 0xdead000000000000, wantLen: 16},
		{cidr: "fe80::1/64", wantHi: 0xfe80000000000000, wantLo: 1, wantLen: 64},
		{cidr: "2620:10f:d000:100::5/128", wantHi: 0x2620010fd0000100, wantLo: 5, wantLen: 128},
		{cidr: "::1/128", wantLo: 1, wantLen: 128},
		{cidr: "::/0", wantLen: 0},

		{cidr: "1.2.3.4", wantLo: 0x0000ffff01020304, wantLen: 128},
		{cidr: "1.2.3.4/32", wantLo: 0x0000ffff01020304, wantLen: 128},
		{cidr: "1.2.3.4/24", wantLo: 0x0000ffff01020304, wantLen: 120},
		{cidr: "1.2.3.4/0", wantLo: 0x0000ffff01020304, wantLen: 96},

		{cidr: "::ffff:1.2.3.4", wantLo: 0x0000ffff01020304, wantLen: 128},
		{cidr: "::ffff:1.2.3.4/120", wantLo: 0x0000ffff01020304, wantLen: 120},
		{cidr: "64:ff9b::1.2.3.4/96", wantHi: 0x0064ff9b00000000, wantLo: 0x01020304, wantLen: 96},

		{cidr: "dead::/129", wantErr: true},
		{cidr: "dead::/016", wantErr: true},
		{cidr: "dead::/0", wantHi: 0xdead000000000000, wantLen: 0},
		{cidr: "dead::/4294967424", wantErr: true}, // 2^32+128: wraps to a valid length
		{cidr: "1.2.3.4/33", wantErr: true},
		{cidr: "dead::/", wantErr: true},
		{cidr: "zz::/16", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.cidr, func(t *testing.T) {
			ip, mask, err := parseCIDR6(stringToBytes(tt.cidr))
			if tt.wantErr {
				require.ErrorIs(t, err, ErrBadIP)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, uint128{hi: tt.wantHi, lo: tt.wantLo}, ip)
			assert.Equal(t, mask128Of(tt.wantLen), mask)
		})
	}
}

// mirrors what the parser considers a mask separator
func splitMask(cidr string) (addr string) {
	if p := maskSep(stringToBytes(cidr)); p > 0 {
		return cidr[:p]
	}
	return cidr
}

func FuzzParseCIDR6(f *testing.F) {
	for _, s := range []string{
		"dead::/16", "fe80::1/64", "::/0", "::ffff:1.2.3.4/120",
		"64:ff9b::1.2.3.4/96", "1.2.3.4/24", "dead::/4294967424",
	} {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, cidr string) {
		_, mask, err := parseCIDR6(stringToBytes(cidr))
		if err != nil {
			return
		}
		n := bits.OnesCount64(mask.hi) + bits.OnesCount64(mask.lo)
		require.Equal(t, mask128Of(n), mask, "non-contiguous mask for %q", cidr)

		addr := splitMask(cidr)
		_, aerr := netip.ParseAddr(addr)
		require.NoError(t, aerr, "accepted %q, netip rejects it", addr)

		if !strings.Contains(addr, ":") {
			require.GreaterOrEqual(t, n, ipv6MaxMaskLength-ipv4MaxMaskLength,
				"bare IPv4 %q got mask shorter than /96", cidr)
		}
	})
}
