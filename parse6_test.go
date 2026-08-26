package nradix

import (
	"encoding/binary"
	"net/netip"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func netipTo128(t *testing.T, addr netip.Addr) uint128 {
	t.Helper()
	b := addr.As16()
	return uint128{binary.BigEndian.Uint64(b[:8]), binary.BigEndian.Uint64(b[8:])}
}

func FuzzParseAddr6(f *testing.F) {
	for _, s := range []string{
		"::", "::1", "1:2:3:4:5:6:7:8", "1::8", "fe80::1%eth0", "fe80::1%25eth0",
		"::ffff:1.2.3.4", "::1.2.3.4", "1.2.3.4", "1:2:3:4:5:6:1.2.3.4",
		"::ffff:0:1.2.3.4", "0001:0002::", "a:b:c:d:e:f:0:1", "0:0:0:0:0:0:0:1",
		"1:2:3:4:5:6:7:8:9", "1:2:3:4:5:6:7", "1::2::3", "12345::", "::%eth0",
		"1:2:", ":1:2", "1.2.3.010", "fe80::1%", "%eth0", "",
	} {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, s string) {
		if !strings.Contains(s, ":") {
			return // bare IPv4 is the caller's business, not this parser's
		}

		got, err := parseAddr6(stringToBytes(s))
		want, werr := netip.ParseAddr(s)

		if werr != nil {
			require.Error(t, err, "netip rejects %q, we accepted %x%x", s, got.hi, got.lo)
			return
		}
		require.NoError(t, err, "netip accepts %q, we rejected it", s)
		require.Equal(t, netipTo128(t, want), got, "value mismatch for %q", s)
	})
}
