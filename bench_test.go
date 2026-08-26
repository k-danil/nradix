package nradix

import (
	"fmt"
	"math/rand"
	"net/netip"
	"testing"
)

const benchSeed = 20240826

func randTable4(n int) (tr *Tree[int], hits, misses []uint32) {
	r := rand.New(rand.NewSource(benchSeed))
	tr = NewTree4[int](n * 2)
	hits = make([]uint32, 0, n)
	misses = make([]uint32, 0, n)
	for i := range n {
		ip := r.Uint32()
		plen := 8 + r.Intn(17)
		tr.v4.insert(ip, mask32Of(plen), i, true)
		hits = append(hits, ip)
		misses = append(misses, ip^0x55000000)
	}
	return
}

func randTable6(n int) (tr *Tree[int], hits, misses []netip.Addr) {
	r := rand.New(rand.NewSource(benchSeed))
	tr = NewTree6[int](n * 2)
	hits = make([]netip.Addr, 0, n)
	misses = make([]netip.Addr, 0, n)
	var b [16]byte
	for i := range n {
		hi, lo := r.Uint64(), r.Uint64()
		tr.v6.insert(uint128{hi, lo}, mask128Of(32+r.Intn(33)), i, true)
		for j := range 8 {
			b[j] = byte(hi >> (56 - 8*j))
			b[8+j] = byte(lo >> (56 - 8*j))
		}
		hits = append(hits, netip.AddrFrom16(b))
		b[0] ^= 0x55
		misses = append(misses, netip.AddrFrom16(b))
	}
	return
}

func BenchmarkTable(b *testing.B) {
	for _, n := range []int{1000, 10_000, 100_000} {
		tr4, hits4, miss4 := randTable4(n)
		tr6, hits6, miss6 := randTable6(n)

		b.Run(fmt.Sprintf("ipv4/%d/hit", n), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				tr4.Find32(hits4[i%len(hits4)])
			}
		})
		b.Run(fmt.Sprintf("ipv4/%d/miss", n), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				tr4.Find32(miss4[i%len(miss4)])
			}
		})
		b.Run(fmt.Sprintf("ipv6/%d/hit", n), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				tr6.FindAddr(hits6[i%len(hits6)])
			}
		})
		b.Run(fmt.Sprintf("ipv6/%d/miss", n), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				tr6.FindAddr(miss6[i%len(miss6)])
			}
		})
	}
}

func BenchmarkParse(b *testing.B) {
	var (
		ip4, mask4 uint32
		ip6, mask6 uint128
		err        error
	)

	cases := []struct {
		name string
		run  func()
	}{
		{"ipv4/host", func() { ip4, err = loadIP4(stringToBytes("192.168.100.200")) }},
		{"ipv4/cidr", func() { ip4, mask4, err = parseCIDR4(stringToBytes("10.1.2.0/24")) }},
		{"ipv6/addr", func() { ip6, err = parseAddr6(stringToBytes("2620:10f:d000:100::5")) }},
		{"ipv6/full", func() { ip6, err = parseAddr6(stringToBytes("2001:db8:85a3:0:0:8a2e:370:7334")) }},
		{"ipv6/cidr", func() { ip6, mask6, err = parseCIDR6("2620:10f:d000:100::5/64") }},
		{"ipv6/mapped4", func() { ip6, mask6, err = parseCIDR6("1.2.3.4/24") }},
	}

	for _, c := range cases {
		b.Run(c.name, func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				c.run()
			}
		})
	}
	_, _, _, _, _ = ip4, mask4, ip6, mask6, err
}

func BenchmarkBuild(b *testing.B) {
	const n = 10_000
	r := rand.New(rand.NewSource(benchSeed))
	ips := make([]uint32, n)
	plens := make([]int, n)
	for i := range n {
		ips[i], plens[i] = r.Uint32(), 8+r.Intn(17)
	}

	b.Run("ipv4/10000", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			tr := NewTree4[int](0)
			for j := range n {
				tr.v4.insert(ips[j], mask32Of(plens[j]), j, true)
			}
		}
	})
}

func BenchmarkCompact(b *testing.B) {
	for _, n := range []int{10_000, 100_000, 1_000_000} {
		tr, hits, _ := randTable4(n)

		b.Run(fmt.Sprintf("%d/before", n), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				tr.Find32(hits[i%len(hits)])
			}
		})

		tr.Compact()

		b.Run(fmt.Sprintf("%d/after", n), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				tr.Find32(hits[i%len(hits)])
			}
		})

		b.Run(fmt.Sprintf("%d/cost", n), func(b *testing.B) {
			fresh, _, _ := randTable4(n)
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				fresh.Compact()
			}
		})
	}
}
