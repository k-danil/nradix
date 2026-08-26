package nradix

import (
	"testing"

	"github.com/stretchr/testify/require"
)

const (
	opCount = 5

	fuzz4OpSize = 6
	fuzz4MaxOps = 64
	fuzz6OpSize = 8
	fuzz6MaxOps = 32
)

type key4 struct {
	ip   uint32
	plen uint8
}

type model4 map[key4]int

func (m model4) insert(ip uint32, plen uint8, val int, overwrite bool) error {
	k := key4{ip & mask4(plen), plen}
	if _, busy := m[k]; busy && !overwrite {
		return ErrNodeBusy
	}
	m[k] = val
	return nil
}

func (m model4) delete(ip uint32, plen uint8) error {
	k := key4{ip & mask4(plen), plen}
	if _, ok := m[k]; !ok {
		return ErrNotFound
	}
	delete(m, k)
	return nil
}

func (m model4) deleteRange(ip uint32, plen uint8) error {
	base := ip & mask4(plen)
	victims := make([]key4, 0, len(m))
	for k := range m {
		if k.plen >= plen && k.ip&mask4(plen) == base {
			victims = append(victims, k)
		}
	}
	if len(victims) == 0 {
		return ErrNotFound
	}
	for _, k := range victims {
		delete(m, k)
	}
	return nil
}

func (m model4) find(ip uint32, plen uint8) (val int, found bool) {
	ip &= mask4(plen)
	best := -1
	for k, v := range m {
		if k.plen <= plen && ip&mask4(k.plen) == k.ip && int(k.plen) > best {
			best, val, found = int(k.plen), v, true
		}
	}
	return
}

func checkNode4[T any](t *testing.T, n, parent *node4[T]) {
	t.Helper()
	if n == nil {
		return
	}
	require.Equal(t, n.prefix&mask4(n.plen), n.prefix, "prefix has bits below /%d", n.plen)
	if parent != nil {
		require.Greater(t, n.plen, parent.plen, "plen must grow downwards")
		require.GreaterOrEqual(t, cpl4(n.prefix, parent.prefix), parent.plen, "child must extend parent prefix")
		require.Equal(t, n == parent.right, bit4(n.prefix, parent.plen), "child hangs on the wrong side")
		require.True(t, n.set || n.forks(), "valueless node must fork, otherwise it should have collapsed")
	}
	checkNode4(t, n.left, n)
	checkNode4(t, n.right, n)
}

func FuzzTree4(f *testing.F) {
	f.Add([]byte{0, 1, 2, 3, 0, 24, 0, 1, 2, 3, 128, 25, 3, 1, 2, 3, 0, 24})
	f.Add([]byte{0, 1, 2, 3, 0, 25, 0, 1, 2, 3, 128, 25, 2, 1, 2, 3, 0, 25, 4, 1, 2, 3, 128, 32})
	f.Add([]byte{0, 10, 0, 0, 1, 32, 0, 10, 0, 0, 3, 32, 4, 10, 0, 0, 1, 31})
	f.Add([]byte{0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 32, 3, 0, 0, 0, 0, 0})

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > fuzz4OpSize*fuzz4MaxOps {
			data = data[:fuzz4OpSize*fuzz4MaxOps]
		}

		tr := NewTree4[int](0)
		want := model4{}

		for i := 0; i+fuzz4OpSize <= len(data); i += fuzz4OpSize {
			ip := uint32(data[i+1])<<24 | uint32(data[i+2])<<16 |
				uint32(data[i+3])<<8 | uint32(data[i+4])
			plen := data[i+5] % (ipv4MaxMaskLength + 1)
			mask := mask32Of(int(plen))

			switch data[i] % opCount {
			case 0:
				a, b := tr.v4.insert(ip, mask, i, false), want.insert(ip, plen, i, false)
				if a != b {
					require.Equal(t, b, a, "add %08x/%d", ip, plen)
				}
			case 1:
				a, b := tr.v4.insert(ip, mask, i, true), want.insert(ip, plen, i, true)
				if a != b {
					require.Equal(t, b, a, "set %08x/%d", ip, plen)
				}
			case 2:
				a, b := tr.v4.delete(ip, mask, false), want.delete(ip, plen)
				if a != b {
					require.Equal(t, b, a, "delete %08x/%d", ip, plen)
				}
			case 3:
				a, b := tr.v4.delete(ip, mask, true), want.deleteRange(ip, plen)
				if a != b {
					require.Equal(t, b, a, "deleteRange %08x/%d", ip, plen)
				}
			case 4:
				av, af := tr.v4.find(ip, mask)
				bv, bf := want.find(ip, plen)
				if af != bf || (bf && av != bv) {
					require.Equal(t, []any{bf, bv}, []any{af, av}, "find %08x/%d", ip, plen)
				}
			}

			checkNode4(t, tr.v4.root, nil)

			for probe := 0; probe <= ipv4MaxMaskLength; probe++ {
				av, af := tr.v4.find(ip, mask32Of(probe))
				bv, bf := want.find(ip, uint8(probe))
				if af != bf || (bf && av != bv) {
					require.Equal(t, []any{bf, bv}, []any{af, av}, "probe %08x/%d", ip, probe)
				}
			}
		}
	})
}

type key6 struct {
	ip   uint128
	plen uint8
}

type model6 map[key6]int

func (m model6) insert(ip uint128, plen uint8, val int, overwrite bool) error {
	k := key6{and128(ip, mask128(plen)), plen}
	if _, busy := m[k]; busy && !overwrite {
		return ErrNodeBusy
	}
	m[k] = val
	return nil
}

func (m model6) delete(ip uint128, plen uint8) error {
	k := key6{and128(ip, mask128(plen)), plen}
	if _, ok := m[k]; !ok {
		return ErrNotFound
	}
	delete(m, k)
	return nil
}

func (m model6) deleteRange(ip uint128, plen uint8) error {
	base := and128(ip, mask128(plen))
	victims := make([]key6, 0, len(m))
	for k := range m {
		if k.plen >= plen && and128(k.ip, mask128(plen)) == base {
			victims = append(victims, k)
		}
	}
	if len(victims) == 0 {
		return ErrNotFound
	}
	for _, k := range victims {
		delete(m, k)
	}
	return nil
}

func (m model6) find(ip uint128, plen uint8) (val int, found bool) {
	ip = and128(ip, mask128(plen))
	best := -1
	for k, v := range m {
		if k.plen <= plen && and128(ip, mask128(k.plen)) == k.ip && int(k.plen) > best {
			best, val, found = int(k.plen), v, true
		}
	}
	return
}

func checkNode6[T any](t *testing.T, n, parent *node6[T]) {
	t.Helper()
	if n == nil {
		return
	}
	require.Equal(t, and128(n.prefix, mask128(n.plen)), n.prefix, "prefix has bits below /%d", n.plen)
	if parent != nil {
		require.Greater(t, n.plen, parent.plen, "plen must grow downwards")
		require.GreaterOrEqual(t, cpl128(n.prefix, parent.prefix), parent.plen, "child must extend parent prefix")
		require.Equal(t, n == parent.right, bit128(n.prefix, parent.plen), "child hangs on the wrong side")
		require.True(t, n.set || n.forks(), "valueless node must fork, otherwise it should have collapsed")
	}
	checkNode6(t, n.left, n)
	checkNode6(t, n.right, n)
}

func FuzzTree6(f *testing.F) {
	f.Add([]byte{0, 0x26, 0x20, 1, 0x0f, 0, 0, 32, 0, 0x26, 0x20, 1, 0x0f, 0, 5, 128, 4, 0x26, 0x20, 1, 0x0f, 0, 5, 128})
	f.Add([]byte{0, 0, 0, 0, 1, 0, 0, 63, 0, 0, 0, 0, 1, 0, 0, 65, 2, 0, 0, 0, 1, 0, 0, 63})
	f.Add([]byte{0, 0, 0, 0, 0, 0x80, 0, 64, 0, 0, 0, 0, 0, 0x40, 0, 66, 3, 0, 0, 0, 0, 0, 0, 64})
	f.Add([]byte{0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 128, 3, 0, 0, 0, 0, 0, 0, 0})

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > fuzz6OpSize*fuzz6MaxOps {
			data = data[:fuzz6OpSize*fuzz6MaxOps]
		}

		tr := NewTree6[int](0)
		want := model6{}

		for i := 0; i+fuzz6OpSize <= len(data); i += fuzz6OpSize {
			ip := uint128{
				hi: uint64(data[i+1])<<56 | uint64(data[i+2])<<48 | uint64(data[i+3])<<32 | uint64(data[i+4]),
				lo: uint64(data[i+5])<<56 | uint64(data[i+6]),
			}
			plen := data[i+7] % (ipv6MaxMaskLength + 1)
			mask := mask128Of(int(plen))

			switch data[i] % opCount {
			case 0:
				a, b := tr.v6.insert(ip, mask, i, false), want.insert(ip, plen, i, false)
				if a != b {
					require.Equal(t, b, a, "add %016x%016x/%d", ip.hi, ip.lo, plen)
				}
			case 1:
				a, b := tr.v6.insert(ip, mask, i, true), want.insert(ip, plen, i, true)
				if a != b {
					require.Equal(t, b, a, "set %016x%016x/%d", ip.hi, ip.lo, plen)
				}
			case 2:
				a, b := tr.v6.delete(ip, mask, false), want.delete(ip, plen)
				if a != b {
					require.Equal(t, b, a, "delete %016x%016x/%d", ip.hi, ip.lo, plen)
				}
			case 3:
				a, b := tr.v6.delete(ip, mask, true), want.deleteRange(ip, plen)
				if a != b {
					require.Equal(t, b, a, "deleteRange %016x%016x/%d", ip.hi, ip.lo, plen)
				}
			case 4:
				av, af := tr.v6.find(ip, mask)
				bv, bf := want.find(ip, plen)
				if af != bf || (bf && av != bv) {
					require.Equal(t, []any{bf, bv}, []any{af, av}, "find %016x%016x/%d", ip.hi, ip.lo, plen)
				}
			}

			checkNode6(t, tr.v6.root, nil)

			for probe := 0; probe <= ipv6MaxMaskLength; probe++ {
				av, af := tr.v6.find(ip, mask128Of(probe))
				bv, bf := want.find(ip, uint8(probe))
				if af != bf || (bf && av != bv) {
					require.Equal(t, []any{bf, bv}, []any{af, av}, "probe %016x%016x/%d", ip.hi, ip.lo, probe)
				}
			}
		}
	})
}
