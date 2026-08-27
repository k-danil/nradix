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
| `Compact()` | rebuild the tree for faster lookups (see below) |

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
| `FindCIDR` (parses the string) | 22 ns | 36 ns |
| `FindAddr` | 6.0 ns | 6.2 ns |
| `Find32` | 4.4 ns | — |

Against realistic tables of random prefixes, where cache misses dominate:

| prefixes | IPv4 | IPv6 |
|---|---|---|
| 1 000 | 39 ns | 40 ns |
| 10 000 | 72 ns | 62 ns |
| 100 000 | 102 ns | 115 ns |

Lookups never allocate. CIDR strings are parsed by a hand-rolled parser rather
than `net/netip`, which is where the gap between `FindCIDR` and `FindAddr`
comes from — pass a `netip.Addr` or a `uint32` when you already have one.

The tree is path-compressed, so a chain of single-child nodes collapses into one
edge and lookup cost follows the number of distinct branch points rather than
the prefix length. Node count is bounded by `2N-1` for `N` stored prefixes,
regardless of mask lengths: 10 000 IPv6 prefixes occupy 19 999 nodes and under
1 MB.

### Compact

Lookups walk from the root down, so a tree is fastest when each node sits next
to its descendants. Insertions cannot arrange that — they lay nodes out in the
order prefixes arrive. `Compact` rebuilds the tree in a fresh arena in traversal
order and reclaims whatever deletions left behind:

| prefixes | before | after | cost |
|---|---|---|---|
| 10 000 | 87.0 ns | 85.6 ns | 0.2 ms |
| 100 000 | 124.6 ns | 117.7 ns | 1.6 ms |
| 1 000 000 | 286.0 ns | 221.0 ns | 10.1 ms |

Small trees fit in cache and gain nothing; the win appears once the tree stops
fitting. Call it after loading a table, not on one that keeps changing.

Nodes come from an internal arena and deleted ones are recycled, so a steady
workload does not allocate. A deleted prefix drops its value immediately rather
than holding it until the node is reused.

Note that the tree stays visible to the garbage collector: nodes contain
pointers, so every mark cycle walks them. On a 100 000-prefix tree that costs
roughly 0.6 ms per cycle, and about twice that if `T` itself contains pointers.
If GC pressure matters to you, store something pointer-free — an index into
your own slice rather than the pointer itself.

## Compared to the original

Against [asergeyev/nradix](https://github.com/asergeyev/nradix), same prefixes,
same host lookups through `FindCIDR`, after `Compact`:

**IPv4** — depends on how deep the prefixes go:

| prefix lengths | count | original | this |
|---|---|---|---|
| /8–/24 | 10 000 | **93.6 ns** | 115.8 |
| /8–/24 | 100 000 | **135.7 ns** | 150.3 |
| /24–/32 | 10 000 | 126.3 ns | **109.0** |
| /24–/32 | 100 000 | 184.2 ns | **167.8** |
| /32 only | 10 000 | 142.5 ns | **106.3** |
| /32 only | 100 000 | 193.5 ns | **155.0** |

Short IPv4 masks are where the original wins, and the reason is a trade-off
rather than an accident. A compressed node costs more to visit — it compares a
stored prefix instead of just picking a bit — so compression only pays once it
removes enough steps to cover that. Average steps to resolve a host lookup:

| prefix lengths | uncompressed | compressed |
|---|---|---|
| /8–/24 | 15.7 | 9.5 |
| /24–/32 | 28.5 | 9.6 |
| /32 only | 32.0 | 9.0 |

A shallow tree of short prefixes has few single-child chains to collapse, so
1.7× fewer steps does not cover the pricier step. The deeper the prefixes, the
better it gets — which is also why IPv6, at up to 128 levels, gains the most.

**IPv6** — this is what the rewrite was for:

| prefixes | original | this |
|---|---|---|
| 10 000 | 369.0 ns | **126.6** |
| 100 000 | 458.6 ns | **231.0** |

**Memory**, 100 000 prefixes:

| | original | this |
|---|---|---|
| IPv4 /8–/24 | 12.8 MB | **3.4 MB** |
| IPv6 /32–/64 | 131.8 MB | **9.6 MB** |

Beyond the numbers: values are generic rather than `interface{}`, so storing
them does not box; `Find32` and `FindAddr` skip parsing altogether; and the
IPv4 parser rejects malformed input the original accepts.

Measured on an Apple M1 Pro, Go 1.27, `FindCIDR` with random host addresses.

## Origin

Forked from [asergeyev/nradix](https://github.com/asergeyev/nradix), originally
a Go translation of nginx's radix tree.

Little of the original code remains: the tree is generic over the value type,
IPv6 is supported, paths are compressed, the CIDR parser was rewritten from
scratch, and lookups can bypass parsing entirely. The public API kept its
shape, and the MIT license and copyright of the original author are retained.

## License

MIT — see [LICENSE](LICENSE).
