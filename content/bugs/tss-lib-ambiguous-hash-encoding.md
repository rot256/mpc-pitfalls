---
title: "bnb-chain/tss-lib variadic `SHA512_256`"
category: cryptographic-primitives
subcategory: "Ambiguous Hash Encoding"
date: 2023-03-24
primitives: [hash, zkp]
repository: https://github.com/bnb-chain/tss-lib
pr: 233
hidden: false
---

The audit finding KS-IOF-F-02 pointed out that bnb-chain's `tss-lib` applied an ambiguous encoding by using a single `'$'`
delimiter with no per-element length tag
([source](https://github.com/bnb-chain/tss-lib/blob/v1.3.5/common/hash.go#L22-L51)):

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

The collision: `SHA512_256([]byte("a$"), []byte("b"))` and `SHA512_256([]byte("a"), []byte("$b"))`
both serialize to `a$$b$` and therefore produce the same digest. The
fix (IoFinnet's commit [`369ec50`](https://github.com/IoFinnet/threshlib/commit/369ec50be1437588a9733443bcb2f15b794601d4),
imported into bnb-chain/tss-lib as
[PR #233](https://github.com/bnb-chain/tss-lib/pull/233)) appends an 8-byte length
tag after each delimiter
([source](https://github.com/bnb-chain/tss-lib/blob/v2.0.0/common/hash.go#L22-L56)):

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
