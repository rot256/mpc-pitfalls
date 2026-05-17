---
title: "Variable-Length List Hashed Without Per-Element Length Prefix"
class: cryptographic-primitives
hidden: true
source: "hash-functions.md"
primitives: [hash, zkp]
---

### Variable-Length List Hashed Without Per-Element Length Prefix

**What can go wrong.** When a hash function accepts a variadic list of byte strings
with only a single delimiter byte between elements — and no per-element length tag —
different input tuples can serialize to the same concatenated byte sequence and
therefore produce the same hash. The encoding is not injective: two distinct inputs
map to one hash value.

**Security implication.** An adversary can craft two structurally different proof
inputs whose byte representations collide. A proof honestly computed for statement
$S_1$ produces the same challenge hash as a statement $S_2$ the adversary constructs,
so a verifier checking a proof for $S_2$ accepts the bytes of a proof for $S_1$. This
collision was a precondition for the TSSHOCK α-shuffle attack class — the attack needs
two proof inputs that hash identically to forge a range proof.

**How to avoid.** Make the encoding injective by appending a fixed-width length tag
after each element (or equivalently, length-prefixing each element before it is
serialised). An 8-byte little-endian length tag after each delimiter is enough to
disambiguate any two distinct input tuples, even when some element happens to contain
the delimiter byte.

**Example: tss-lib KS-IOF-F-02.** The vulnerable variadic hash used a single `'$'`
delimiter with no length tag
([source](https://github.com/bnb-chain/tss-lib/blob/v1.3.5/common/hash.go)):

```go
// common/hash.go — bnb-chain/tss-lib v1.3.5 (vulnerable)
const hashInputDelimiter = byte('$')

func SHA512_256(in ...[]byte) []byte {
    inLenBz := make([]byte, 8)
    binary.LittleEndian.PutUint64(inLenBz, uint64(len(in))) // counts inputs, not sizes
    data = append(data, inLenBz...)
    for _, bz := range in {
        data = append(data, bz...)
        data = append(data, hashInputDelimiter) // no length tag per element
    }
}
```

The collision: `SHA512_256([]byte("a$"), []byte("b"))` and `SHA512_256([]byte("a"),
[]byte("$b"))` both serialise to `a$$b$` and therefore produce the same digest. The
fix (IoFinnet [commit `369ec50`](https://github.com/IoFinnet/threshlib/commit/369ec50be1437588a9733443bcb2f15b794601d4),
imported into bnb-chain/tss-lib as
[PR #233](https://github.com/bnb-chain/tss-lib/pull/233)) appends an 8-byte length
tag after each delimiter
([source](https://github.com/bnb-chain/tss-lib/blob/v2.0.0/common/hash.go)):

```go
// common/hash.go — bnb-chain/tss-lib v2.0.0 (fixed)
for _, bz := range in {
    data = append(data, bz...)
    data = append(data, hashInputDelimiter)
    dataLen := make([]byte, 8)
    binary.LittleEndian.PutUint64(dataLen, uint64(len(bz)))
    data = append(data, dataLen...) // length tag makes encoding injective
}
```
