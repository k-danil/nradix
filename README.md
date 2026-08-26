# nradix

Radix tree for IPv4 and IPv6 CIDR lookup: store a value per prefix, then find
the longest prefix matching a given address.

```go
tree := nradix.NewTree4[string](0)

tree.AddCIDR("10.0.0.0/8", "corp")
tree.AddCIDR("10.1.2.0/24", "office")

owner, _ := tree.FindCIDR("10.1.2.55") // "office" — the most specific match wins
owner, _ = tree.FindCIDR("10.9.9.9")   // "corp"

_, err := tree.FindCIDR("192.0.2.1")   // errors.Is(err, nradix.ErrNotFound)
```

## Install

```
go get github.com/k-danil/nradix
```

Requires Go 1.26 or newer. No runtime dependencies.

## API

A tree is created for one address family and holds values of any type `T`.
`preallocate` reserves room for that many nodes up front; pass `0` to let the
tree grow on its own.

```go
func NewTree4[T any](preallocate int) *Tree[T]
func NewTree6[T any](preallocate int) *Tree[T]
```

| method | |
|---|---|
| `AddCIDR(cidr string, val T) error` | insert; `ErrNodeBusy` if the prefix already holds a value |
| `SetCIDR(cidr string, val T) error` | insert or overwrite |
| `FindCIDR(cidr string) (T, error)` | longest prefix match; `ErrNotFound` if nothing covers it |
| `Find32(ip uint32) (T, error)` | same, for an IPv4 host address already in binary form |
| `FindAddr(addr netip.Addr) (T, error)` | same, for a `netip.Addr` |
| `DeleteCIDR(cidr string) error` | remove the value stored at exactly this prefix |
| `DeleteWholeRangeCIDR(cidr string) error` | remove this prefix and everything under it |

`Find32` and `FindAddr` skip string parsing entirely, which is worth a lot —
see below. Both take a host address, so they match `/32` and `/128` lookups.

Prefixes are parsed strictly: leading zeros in an IPv4 octet are rejected, so
`1.2.3.010` is an error rather than `1.2.3.10` — the two readings of that string
are exactly what ACL bypasses are built on.

An IPv4 tree accepts IPv4 and IPv4-mapped addresses and reports `ErrBadIP` for
anything else. An IPv6 tree accepts bare IPv4 too, matching it in its
IPv4-mapped form, so `AddCIDR("1.2.3.0/24", …)` on an IPv6 tree stores
`::ffff:1.2.3.0/120`.

## Thread safety

**None.** A `Tree` is not safe for concurrent use, not even for concurrent
readers alongside a single writer. Guard it yourself if you need it — the
library deliberately makes no choice for you.

## Performance

Apple M1 Pro, Go 1.27, single lookup:

Single lookup against a handful of prefixes:

| | IPv4 | IPv6 |
|---|---|---|
| `FindCIDR` (parses the string) | 22 ns | 39 ns |
| `FindAddr` | 6.3 ns | 7.6 ns |
| `Find32` | 4.8 ns | — |

Against realistic tables of random prefixes, where cache misses dominate:

| prefixes | IPv4 | IPv6 |
|---|---|---|
| 1 000 | 46 ns | 55 ns |
| 10 000 | 93 ns | 93 ns |
| 100 000 | 125 ns | 161 ns |

Lookups never allocate. CIDR strings are parsed by a hand-rolled parser rather
than `net/netip`, which is where the gap between `FindCIDR` and `FindAddr`
comes from — pass a `netip.Addr` or a `uint32` when you already have one.

The tree is path-compressed, so a chain of single-child nodes collapses into one
edge and lookup cost follows the number of distinct branch points rather than
the prefix length. Node count is bounded by `2N-1` for `N` stored prefixes,
regardless of mask lengths: 10 000 IPv6 prefixes occupy 19 999 nodes and under
1 MB.

Nodes come from an internal arena and deleted ones are recycled, so a steady
workload does not allocate. A deleted prefix drops its value immediately rather
than holding it until the node is reused.

Note that the tree stays visible to the garbage collector: nodes contain
pointers, so every mark cycle walks them. On a 100 000-prefix tree that costs
roughly 0.6 ms per cycle, and about twice that if `T` itself contains pointers.
If GC pressure matters to you, store something pointer-free — an index into
your own slice rather than the pointer itself.

## Origin

Forked from [asergeyev/nradix](https://github.com/asergeyev/nradix), originally
a Go translation of nginx's radix tree.

Little of the original code remains: the tree is generic over the value type,
IPv6 is supported, paths are compressed, the CIDR parser was rewritten from
scratch, and lookups can bypass parsing entirely. The public API kept its
shape, and the MIT license and copyright of the original author are retained.

## License

MIT — see [LICENSE](LICENSE).
