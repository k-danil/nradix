// Copyright (C) 2015 Alex Sergeyev
// This project is licensed under the terms of the MIT license.
// Read LICENSE file for information for all notices and permissions.

package nradix

import (
	"testing"

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
	tr := NewTree[int](0, false)

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
	runSteps(t, NewTree[int](0, false), []step{
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
	runSteps(t, NewTree[int](0, false), []step{
		{op: opAdd, cidr: "1.1.1.0/24", val: 1},
		{op: opDelete, cidr: "1.1.1.0/24"},
		{op: opAdd, cidr: "1.1.1.0/25", val: 2},
		{op: opFind, cidr: "1.1.1.128", err: ErrNotFound},
	})
}

func TestTree6(t *testing.T) {
	runSteps(t, NewTree[int](0, true), []step{
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
	runSteps(t, NewTree[int](0, true), []step{
		{op: opAdd, cidr: "2620:10f::/32", val: 54321},
		{op: opAdd, cidr: "2620:10f:d000:100::5/128", val: 12345},
		{op: opFind, cidr: "2620:10f:d000:100::5/128", val: 12345},
	})
}

func BenchmarkTree_FindCIDR_ipv6(b *testing.B) {
	tr := NewTree[int](0, true)
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
	tr := NewTree[struct{}](200, false)
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
