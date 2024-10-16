// Copyright (C) 2015 Alex Sergeyev
// This project is licensed under the terms of the MIT license.
// Read LICENSE file for information for all notices and permissions.

package nradix

import (
	"errors"
	"log"
	"testing"
)

func TestTree(t *testing.T) {
	tr := NewTree[int](0, false)
	if tr == nil || tr.root == nil {
		t.Error("Did not create tree properly")
	}
	err := tr.AddCIDR("1.2.3.0/25", 1)
	if err != nil {
		t.Error(err)
	}

	// Matching defined cidr
	var inf int
	inf, err = tr.FindCIDR("1.2.3.1/25")
	if err != nil {
		t.Error(err)
	}
	if inf != 1 {
		t.Errorf("Wrong value, expected 1, got %v", inf)
	}

	// Inside defined cidr
	inf, err = tr.FindCIDR("1.2.3.60/32")
	if err != nil {
		t.Error(err)
	}
	if inf != 1 {
		t.Errorf("Wrong value, expected 1, got %v", inf)
	}
	inf, err = tr.FindCIDR("1.2.3.60")
	if err != nil {
		t.Error(err)
	}
	if inf != 1 {
		t.Errorf("Wrong value, expected 1, got %v", inf)
	}

	// Outside defined cidr
	_, err = tr.FindCIDR("1.2.3.160/32")
	if !errors.Is(err, ErrNotFound) {
		t.Error(err)
	}

	_, err = tr.FindCIDR("1.2.3.160")
	if !errors.Is(err, ErrNotFound) {
		t.Error(err)
	}

	_, err = tr.FindCIDR("1.2.3.128/25")
	if !errors.Is(err, ErrNotFound) {
		t.Error(err)
	}

	// Covering not defined
	_, err = tr.FindCIDR("1.2.3.0/24")
	if !errors.Is(err, ErrNotFound) {
		t.Error(err)
	}

	// Covering defined
	err = tr.AddCIDR("1.2.3.0/24", 2)
	if err != nil {
		t.Error(err)
	}
	inf, err = tr.FindCIDR("1.2.3.0/24")
	if err != nil {
		t.Error(err)
	}
	if inf != 2 {
		t.Errorf("Wrong value, expected 2, got %v", inf)
	}

	inf, err = tr.FindCIDR("1.2.3.160/32")
	if err != nil {
		t.Error(err)
	}
	if inf != 2 {
		t.Errorf("Wrong value, expected 2, got %v", inf)
	}

	// Hit both covering and internal, should choose most specific
	inf, err = tr.FindCIDR("1.2.3.0/32")
	if err != nil {
		t.Error(err)
	}
	if inf != 1 {
		t.Errorf("Wrong value, expected 1, got %v", inf)
	}

	// Delete internal
	err = tr.DeleteCIDR("1.2.3.0/25")
	if err != nil {
		t.Error(err)
	}

	// Hit covering with old IP
	inf, err = tr.FindCIDR("1.2.3.0/32")
	if err != nil {
		t.Error(err)
	}
	if inf != 2 {
		t.Errorf("Wrong value, expected 2, got %v", inf)
	}

	// Add internal back in
	err = tr.AddCIDR("1.2.3.0/25", 1)
	if err != nil {
		t.Error(err)
	}

	// Delete covering
	err = tr.DeleteCIDR("1.2.3.0/24")
	if err != nil {
		t.Error(err)
	}

	// Hit with old IP
	inf, err = tr.FindCIDR("1.2.3.0/32")
	if err != nil {
		t.Error(err)
	}
	if inf != 1 {
		t.Errorf("Wrong value, expected 1, got %v", inf)
	}

	// Find covering again
	_, err = tr.FindCIDR("1.2.3.0/24")
	if !errors.Is(err, ErrNotFound) {
		t.Error(err)
	}

	// Add covering back in
	err = tr.AddCIDR("1.2.3.0/24", 2)
	if err != nil {
		t.Error(err)
	}
	inf, err = tr.FindCIDR("1.2.3.0/24")
	if err != nil {
		t.Error(err)
	}
	if inf != 2 {
		t.Errorf("Wrong value, expected 2, got %v", inf)
	}

	// Delete the whole range
	err = tr.DeleteWholeRangeCIDR("1.2.3.0/24")
	if err != nil {
		t.Error(err)
	}
	// should be no value for covering
	_, err = tr.FindCIDR("1.2.3.0/24")
	if !errors.Is(err, ErrNotFound) {
		t.Error(err)
	}
	// should be no value for internal
	_, err = tr.FindCIDR("1.2.3.0/32")
	if !errors.Is(err, ErrNotFound) {
		t.Error(err)
	}
}

func TestSet(t *testing.T) {
	tr := NewTree[int](0, false)
	if tr == nil || tr.root == nil {
		t.Error("Did not create tree properly")
	}

	tr.AddCIDR("1.1.1.0/24", 1)
	inf, err := tr.FindCIDR("1.1.1.0")
	if err != nil {
		t.Error(err)
	}
	if inf != 1 {
		t.Errorf("Wrong value, expected 1, got %v", inf)
	}

	tr.AddCIDR("1.1.1.0/25", 2)
	inf, err = tr.FindCIDR("1.1.1.0")
	if err != nil {
		t.Error(err)
	}
	if inf != 2 {
		t.Errorf("Wrong value, expected 2, got %v", inf)
	}
	inf, err = tr.FindCIDR("1.1.1.0/24")
	if err != nil {
		t.Error(err)
	}
	if inf != 1 {
		t.Errorf("Wrong value, expected 1, got %v", inf)
	}

	// add covering should fail
	err = tr.AddCIDR("1.1.1.0/24", 60)
	if !errors.Is(err, ErrNodeBusy) {
		t.Errorf("Should have gotten ErrNodeBusy, instead got err: %v", err)
	}

	// set covering
	err = tr.SetCIDR("1.1.1.0/24", 3)
	if err != nil {
		t.Error(err)
	}
	inf, err = tr.FindCIDR("1.1.1.0")
	if err != nil {
		t.Error(err)
	}
	if inf != 2 {
		t.Errorf("Wrong value, expected 2, got %v", inf)
	}
	inf, err = tr.FindCIDR("1.1.1.0/24")
	if err != nil {
		t.Error(err)
	}
	if inf != 3 {
		t.Errorf("Wrong value, expected 3, got %v", inf)
	}

	// set internal
	err = tr.SetCIDR("1.1.1.0/25", 4)
	if err != nil {
		t.Error(err)
	}
	inf, err = tr.FindCIDR("1.1.1.0")
	if err != nil {
		t.Error(err)
	}
	if inf != 4 {
		t.Errorf("Wrong value, expected 4, got %v", inf)
	}
	inf, err = tr.FindCIDR("1.1.1.0/24")
	if err != nil {
		t.Error(err)
	}
	if inf != 3 {
		t.Errorf("Wrong value, expected 3, got %v", inf)
	}
}

func TestRegression(t *testing.T) {
	tr := NewTree[int](0, false)
	if tr == nil || tr.root == nil {
		t.Error("Did not create tree properly")
	}

	tr.AddCIDR("1.1.1.0/24", 1)

	tr.DeleteCIDR("1.1.1.0/24")
	tr.AddCIDR("1.1.1.0/25", 2)

	// inside old range, outside new range
	_, err := tr.FindCIDR("1.1.1.128")
	if !errors.Is(err, ErrNotFound) {
		t.Error(err)
	}
}

func TestTree6(t *testing.T) {
	tr := NewTree[int](0, true)
	if tr == nil || tr.root == nil {
		t.Error("Did not create tree properly")
	}
	err := tr.AddCIDR("dead::0/16", 3)
	if err != nil {
		t.Error(err)
	}

	// Matching defined cidr
	var inf int
	inf, err = tr.FindCIDR("dead::beef")
	if err != nil {
		t.Error(err)
	}
	if inf != 3 {
		t.Errorf("Wrong value, expected 3, got %v", inf)
	}

	// Outside
	inf, err = tr.FindCIDR("deed::beef/32")
	if !errors.Is(err, ErrNotFound) {
		t.Error(err)
	}

	// Subnet
	err = tr.AddCIDR("dead:beef::0/48", 4)
	if err != nil {
		t.Error(err)
	}

	// Match defined subnet
	inf, err = tr.FindCIDR("dead:beef::0a5c:0/64")
	if err != nil {
		t.Error(err)
	}
	if inf != 4 {
		t.Errorf("Wrong value, expected 4, got %v", inf)
	}

	// Match outside defined subnet
	inf, err = tr.FindCIDR("dead:0::beef:0a5c:0/64")
	if err != nil {
		t.Error(err)
	}
	if inf != 3 {
		t.Errorf("Wrong value, expected 3, got %v", inf)
	}

}

func TestRegression6(t *testing.T) {
	tr := NewTree[int](0, true)
	if tr == nil || tr.root == nil {
		t.Error("Did not create tree properly")
	}
	// in one of the implementations /128 addresses were causing panic...
	tr.AddCIDR("2620:10f::/32", 54321)
	tr.AddCIDR("2620:10f:d000:100::5/128", 12345)

	inf, err := tr.FindCIDR("2620:10f:d000:100::5/128")
	if err != nil {
		t.Errorf("Could not get /128 address from the tree, error: %s", err)
	} else if inf != 12345 {
		t.Errorf("Wrong value from /128 test, got %d, expected 12345", inf)
	}
}

func BenchmarkTree_FindCIDR_ipv6(b *testing.B) {
	tr := NewTree[int](0, true)
	if tr == nil || tr.root == nil {
		log.Fatalln("Did not create tree properly")
	}

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
	tr := NewTree[int](0, false)
	if tr == nil || tr.root == nil {
		log.Fatalln("Did not create tree properly")
	}

	tr.AddCIDR("1.1.1.0/24", 1)
	tr.AddCIDR("1.1.1.0/25", 2)
	tr.AddCIDR("1.1.1.128", 3)

	b.ReportAllocs()

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
