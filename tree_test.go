// Copyright (C) 2015 Alex Sergeyev
// This project is licensed under the terms of the MIT license.
// Read LICENSE file for information for all notices and permissions.

package nradix

import (
	"fmt"
	"net/netip"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type treeOp uint8

const (
	opAdd treeOp = iota
	opSet
	opDelete
	opDeleteRange
	opFind
)

var opNames = [...]string{
	opAdd:         "add",
	opSet:         "set",
	opDelete:      "delete",
	opDeleteRange: "deleteRange",
	opFind:        "find",
}

func (o treeOp) String() string { return opNames[o] }

type step struct {
	op   treeOp
	cidr string
	val  int
	err  error
}

func runSteps(t *testing.T, tr *Tree[int], steps []step) {
	t.Helper()

	for _, s := range steps {
		var (
			got int
			err error
		)
		switch s.op {
		case opAdd:
			err = tr.AddCIDR(s.cidr, s.val)
		case opSet:
			err = tr.SetCIDR(s.cidr, s.val)
		case opDelete:
			err = tr.DeleteCIDR(s.cidr)
		case opDeleteRange:
			err = tr.DeleteWholeRangeCIDR(s.cidr)
		case opFind:
			got, err = tr.FindCIDR(s.cidr)
		}

		if s.err != nil {
			require.ErrorIs(t, err, s.err, "%s %s", s.op, s.cidr)
			continue
		}
		require.NoError(t, err, "%s %s", s.op, s.cidr)
		if s.op == opFind {
			assert.Equal(t, s.val, got, "%s %s", s.op, s.cidr)
		}
	}
}

func TestTree(t *testing.T) {
	tr := NewTree4[int](0)

	stages := []struct {
		name  string
		steps []step
	}{
		{"add inner /25", []step{
			{op: opAdd, cidr: "1.2.3.0/25", val: 1},
			{op: opFind, cidr: "1.2.3.1/25", val: 1},
			{op: opFind, cidr: "1.2.3.60/32", val: 1},
			{op: opFind, cidr: "1.2.3.60", val: 1},
			{op: opFind, cidr: "1.2.3.160/32", err: ErrNotFound},
			{op: opFind, cidr: "1.2.3.160", err: ErrNotFound},
			{op: opFind, cidr: "1.2.3.128/25", err: ErrNotFound},
			{op: opFind, cidr: "1.2.3.0/24", err: ErrNotFound},
		}},
		{"add covering /24", []step{
			{op: opAdd, cidr: "1.2.3.0/24", val: 2},
			{op: opFind, cidr: "1.2.3.0/24", val: 2},
			{op: opFind, cidr: "1.2.3.160/32", val: 2},
			{op: opFind, cidr: "1.2.3.0/32", val: 1},
		}},
		{"delete inner /25", []step{
			{op: opDelete, cidr: "1.2.3.0/25"},
			{op: opFind, cidr: "1.2.3.0/32", val: 2},
		}},
		{"delete covering /24", []step{
			{op: opAdd, cidr: "1.2.3.0/25", val: 1},
			{op: opDelete, cidr: "1.2.3.0/24"},
			{op: opFind, cidr: "1.2.3.0/32", val: 1},
			{op: opFind, cidr: "1.2.3.0/24", err: ErrNotFound},
		}},
		{"delete whole range", []step{
			{op: opAdd, cidr: "1.2.3.0/24", val: 2},
			{op: opFind, cidr: "1.2.3.0/24", val: 2},
			{op: opDeleteRange, cidr: "1.2.3.0/24"},
			{op: opFind, cidr: "1.2.3.0/24", err: ErrNotFound},
			{op: opFind, cidr: "1.2.3.0/32", err: ErrNotFound},
		}},
	}

	for _, st := range stages {
		t.Run(st.name, func(t *testing.T) {
			runSteps(t, tr, st.steps)
		})
	}
}

func TestSet(t *testing.T) {
	runSteps(t, NewTree4[int](0), []step{
		{op: opAdd, cidr: "1.1.1.0/24", val: 1},
		{op: opFind, cidr: "1.1.1.0", val: 1},
		{op: opAdd, cidr: "1.1.1.0/25", val: 2},
		{op: opFind, cidr: "1.1.1.0", val: 2},
		{op: opFind, cidr: "1.1.1.0/24", val: 1},
		{op: opAdd, cidr: "1.1.1.0/24", val: 60, err: ErrNodeBusy},
		{op: opSet, cidr: "1.1.1.0/24", val: 3},
		{op: opFind, cidr: "1.1.1.0", val: 2},
		{op: opFind, cidr: "1.1.1.0/24", val: 3},
		{op: opSet, cidr: "1.1.1.0/25", val: 4},
		{op: opFind, cidr: "1.1.1.0", val: 4},
		{op: opFind, cidr: "1.1.1.0/24", val: 3},
	})
}

func TestRegression(t *testing.T) {
	runSteps(t, NewTree4[int](0), []step{
		{op: opAdd, cidr: "1.1.1.0/24", val: 1},
		{op: opDelete, cidr: "1.1.1.0/24"},
		{op: opAdd, cidr: "1.1.1.0/25", val: 2},
		{op: opFind, cidr: "1.1.1.128", err: ErrNotFound},
	})
}

func TestTree6(t *testing.T) {
	runSteps(t, NewTree6[int](0), []step{
		{op: opAdd, cidr: "dead::0/16", val: 3},
		{op: opFind, cidr: "dead::beef", val: 3},
		{op: opFind, cidr: "deed::beef/32", err: ErrNotFound},
		{op: opAdd, cidr: "dead:beef::0/48", val: 4},
		{op: opFind, cidr: "dead:beef::0a5c:0/64", val: 4},
		{op: opFind, cidr: "dead:0::beef:0a5c:0/64", val: 3},
	})
}

func TestRegression6(t *testing.T) {
	// in one of the implementations /128 addresses were causing panic
	runSteps(t, NewTree6[int](0), []step{
		{op: opAdd, cidr: "2620:10f::/32", val: 54321},
		{op: opAdd, cidr: "2620:10f:d000:100::5/128", val: 12345},
		{op: opFind, cidr: "2620:10f:d000:100::5/128", val: 12345},
	})
}

func newTestTree(ipv6 bool) *Tree[int] {
	if ipv6 {
		return NewTree6[int](0)
	}
	return NewTree4[int](0)
}

func TestFindWithoutParsing(t *testing.T) {
	const (
		inRange  = 0x01020304
		outRange = 0x01020400
	)

	for _, ipv6 := range []bool{false, true} {
		t.Run(map[bool]string{false: "tree4", true: "tree6"}[ipv6], func(t *testing.T) {
			tr := newTestTree(ipv6)
			require.NoError(t, tr.AddCIDR("1.2.3.0/24", 7))

			got, err := tr.Find32(inRange)
			require.NoError(t, err)
			assert.Equal(t, 7, got)

			for _, s := range []string{"1.2.3.4", "::ffff:1.2.3.4"} {
				got, err = tr.FindAddr(netip.MustParseAddr(s))
				require.NoError(t, err, s)
				assert.Equal(t, 7, got, s)
			}

			_, err = tr.Find32(outRange)
			assert.ErrorIs(t, err, ErrNotFound)
		})
	}

	tr4 := NewTree4[int](0)
	for _, addr := range []netip.Addr{netip.MustParseAddr("dead::beef"), {}} {
		_, err := tr4.FindAddr(addr)
		assert.ErrorIs(t, err, ErrBadIP, addr.String())
	}
}

func TestDeleteReleasesValues(t *testing.T) {
	const n = 500
	var freed atomic.Int64

	tr := NewTree4[*int](0)
	for i := range n {
		v := new(int)
		runtime.AddCleanup(v, func(c *atomic.Int64) { c.Add(1) }, &freed)
		require.NoError(t, tr.AddCIDR(fmt.Sprintf("10.%d.%d.0/24", i/256, i%256), v))
	}
	require.NoError(t, tr.DeleteWholeRangeCIDR("10.0.0.0/8"))

	for range 3 {
		runtime.GC()
		time.Sleep(10 * time.Millisecond)
	}
	// a freed node must not keep its value alive until it is reused
	assert.Greater(t, freed.Load(), int64(n-10))
	runtime.KeepAlive(tr)
}

func BenchmarkTree_FindWithoutParsing(b *testing.B) {
	tr4 := NewTree4[int](0)
	tr4.AddCIDR("1.1.1.0/24", 1)
	tr6 := NewTree6[int](0)
	tr6.AddCIDR("2620:10f::/32", 1)

	addr4 := netip.MustParseAddr("1.1.1.128")
	addr6 := netip.MustParseAddr("2620:10f:d000:100::5")

	b.Run("ipv4/FindCIDR", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			tr4.FindCIDR("1.1.1.128")
		}
	})
	b.Run("ipv4/FindAddr", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			tr4.FindAddr(addr4)
		}
	})
	b.Run("ipv4/Find32", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			tr4.Find32(0x01010180)
		}
	})
	b.Run("ipv6/FindCIDR", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			tr6.FindCIDR("2620:10f:d000:100::5")
		}
	})
	b.Run("ipv6/FindAddr", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			tr6.FindAddr(addr6)
		}
	})
}

func BenchmarkTree_FindCIDR_ipv6(b *testing.B) {
	tr := NewTree6[int](0)
	tr.AddCIDR("2620:10f::/32", 1)
	tr.AddCIDR("2620:10f:d000:100::5", 2)

	b.ReportAllocs()

	b.Run("prefix", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			tr.FindCIDR("2620:10f:d000:100::5/128")
		}
	})
	b.Run("no prefix", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			tr.FindCIDR("2620:10f:d000:100::5")
		}
	})
}

func BenchmarkTree_FindCIDR_ipv4(b *testing.B) {
	tr := NewTree4[struct{}](200)
	tr.AddCIDR("1.1.1.0/24", struct{}{})
	tr.AddCIDR("1.1.1.0/25", struct{}{})
	tr.AddCIDR("1.1.1.128", struct{}{})

	b.ReportAllocs()

	b.Run("big prefix", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			tr.FindCIDR("1.1.1.0/25")
		}
	})
	b.Run("prefix", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			tr.FindCIDR("1.1.1.128/32")
		}
	})
	b.Run("no prefix", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			tr.FindCIDR("1.1.1.128")
		}
	})
}
