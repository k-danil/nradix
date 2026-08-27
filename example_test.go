package nradix_test

import (
	"errors"
	"fmt"
	"net/netip"

	"github.com/k-danil/nradix"
)

func ExampleTree() {
	tree := nradix.NewTree[string](0)

	tree.AddCIDR("10.0.0.0/8", "corp")
	tree.AddCIDR("10.1.2.0/24", "office")

	// the most specific prefix wins
	owner, _ := tree.FindCIDR("10.1.2.55")
	fmt.Println(owner)

	owner, _ = tree.FindCIDR("10.9.9.9")
	fmt.Println(owner)

	if _, err := tree.FindCIDR("192.0.2.1"); errors.Is(err, nradix.ErrNotFound) {
		fmt.Println("no match")
	}

	// Output:
	// office
	// corp
	// no match
}

func ExampleTree_FindAddr() {
	tree := nradix.NewTree[int](0)
	tree.AddCIDR("2001:db8::/32", 1)

	// no string parsing on lookup
	owner, err := tree.FindAddr(netip.MustParseAddr("2001:db8::dead:beef"))
	fmt.Println(owner, err)

	// Output: 1 <nil>
}

func ExampleTree_Find32() {
	tree := nradix.NewTree[int](0)
	tree.AddCIDR("192.0.2.0/24", 42)

	owner, err := tree.Find32(0xC0000201) // 192.0.2.1
	fmt.Println(owner, err)

	// Output: 42 <nil>
}

func ExampleTree_Compact() {
	tree := nradix.NewTree[int](0)
	for i, cidr := range []string{"10.0.0.0/8", "10.1.0.0/16", "10.1.2.0/24"} {
		tree.AddCIDR(cidr, i)
	}

	// worth doing once the table is loaded and no longer changes
	tree.Compact()

	owner, err := tree.FindCIDR("10.1.2.3")
	fmt.Println(owner, err)

	// Output: 2 <nil>
}
