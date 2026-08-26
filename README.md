# nradix

Radix tree for IPv4 and IPv6 CIDR lookup: store a value per prefix, then find
the longest prefix matching a given address.

```go
tree := nradix.NewTree[string](0, false)

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

A tree is created for one address family and holds values of any type `T`:

```go
func NewTree[T any](preallocate uint64, ipv6 bool) *Tree[T]
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

| | IPv4 | IPv6 |
|---|---|---|
| `FindCIDR` (parses the string) | 20 ns | 54 ns |
| `FindAddr` | 6.5 ns | 6.9 ns |
| `Find32` | 4.8 ns | — |

The tree is path-compressed, so a chain of single-child nodes collapses into one
edge and lookup cost follows the number of distinct branch points rather than
the prefix length. Node count is bounded by `2N-1` for `N` stored prefixes,
regardless of mask lengths: 10 000 IPv6 prefixes occupy 19 999 nodes and under
1 MB.

Nodes come from an internal arena and deleted ones are recycled, so a steady
workload does not allocate.

## Origin

Forked from [asergeyev/nradix](https://github.com/asergeyev/nradix), originally
a Go translation of nginx's radix tree.

Little of the original code remains: the tree is generic over the value type,
IPv6 is supported, paths are compressed, the CIDR parser was rewritten, and
lookups can bypass parsing. The public API kept its shape, and the MIT license
and copyright of the original author are retained.

## License

MIT — see [LICENSE](LICENSE).
