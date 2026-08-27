# nradix

Radix tree for IPv4 and IPv6 CIDR lookup: store a value per prefix, then find
the longest prefix matching a given address.

```go
tree := nradix.NewTree[string](0)

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

One tree holds both address families and values of any type `T`. `preallocate`
reserves room for that many nodes up front; pass `0` to let the tree grow on its
own.

```go
func NewTree[T any](preallocate int) *Tree[T]
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
| `Compact()` | rebuild for faster lookups after a table is loaded |

IPv4 prefixes are stored in their IPv4-mapped form, so `AddCIDR("1.2.3.0/24", …)`
and `AddCIDR("::ffff:1.2.3.0/120", …)` name the same entry, and a lookup by
either spelling finds it.

Parsing is strict: leading zeros in an IPv4 octet are rejected, so `1.2.3.010`
is an error rather than `1.2.3.10` — the two readings of that string are what
ACL bypasses are built on.

## Thread safety

**None.** A `Tree` is not safe for concurrent use, not even for concurrent
readers alongside a single writer. Guard it yourself if you need it.

## Performance

Apple M1 Pro, Go 1.27. Lookups never allocate.

| | IPv4 | IPv6 |
|---|---|---|
| `FindCIDR` — parses the string | 25 ns | 35 ns |
| `FindAddr` — takes a `netip.Addr` | 6.3 ns | 6.1 ns |
| `Find32` — takes a raw `uint32` | 4.6 ns | — |

Most of `FindCIDR` is parsing, so pass a `netip.Addr` or a `uint32` whenever you
already have one — it is roughly four times faster.

Against tables of random prefixes, where cache misses dominate:

| prefixes | IPv4 | IPv6 |
|---|---|---|
| 1 000 | 38 ns | 41 ns |
| 10 000 | 73 ns | 64 ns |
| 100 000 | 108 ns | 114 ns |

Paths are compressed, so node count is bounded by `2N-1` for `N` prefixes
regardless of mask lengths, and lookup cost follows the number of branch points
rather than the prefix length.

### Compact

Insertions lay nodes out in the order prefixes arrive, while lookups walk from
the root down. `Compact` rebuilds the tree so each node sits next to its
descendants, and reclaims space left by deletions:

| prefixes | before | after | cost |
|---|---|---|---|
| 10 000 | 70 ns | 68 ns | 0.25 ms |
| 100 000 | 111 ns | 99 ns | 1.5 ms |
| 1 000 000 | 281 ns | 198 ns | 11 ms |

Small trees fit in cache and gain nothing. Call it once after loading a table,
not on one that keeps changing.

### Garbage collector

Nodes contain pointers, so every mark cycle walks the tree — about 0.6 ms per
cycle on 100 000 prefixes, roughly double that if `T` itself contains pointers.
If that matters, store something pointer-free, such as an index into your own
slice rather than the pointer.

## Compared to the original

Against [asergeyev/nradix](https://github.com/asergeyev/nradix): same prefixes,
looked up by host address through `FindCIDR`. `Compact` has no counterpart
upstream, so both columns are shown.

| prefix lengths | count | original | this | after `Compact` |
|---|---|---|---|---|
| IPv4 /8–/24 | 10 000 | **92 ns** | 102 | 101 |
| IPv4 /8–/24 | 100 000 | **126 ns** | 139 | 128 |
| IPv4 /24–/32 | 10 000 | 124 ns | 94 | **92** |
| IPv4 /24–/32 | 100 000 | 167 ns | 150 | **138** |
| IPv4 /32 | 10 000 | 136 ns | 94 | **93** |
| IPv4 /32 | 100 000 | 179 ns | 151 | **136** |
| IPv6 /32–/64 | 10 000 | 363 ns | 93 | **95** |
| IPv6 /32–/64 | 100 000 | 458 ns | 163 | **147** |

Memory on 100 000 prefixes: IPv4 12.8 MB → **5.0 MB**, IPv6 131.8 MB → **9.6 MB**.

Short IPv4 masks are the one shape where the original stays ahead: that tree is
shallow with few chains to compress, and a compressed node costs more to visit.
The deeper the prefixes, the more compression pays, which is why IPv6 — up to
128 levels — gains around four times.

Values are also generic rather than `interface{}`, so storing them does not box,
and lookups can skip parsing entirely.

## Origin

Forked from [asergeyev/nradix](https://github.com/asergeyev/nradix), originally
a Go translation of nginx's radix tree. Little of the original code remains, but
its MIT license and copyright are retained.

## License

MIT — see [LICENSE](LICENSE).
