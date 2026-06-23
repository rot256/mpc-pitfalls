---
title: "bnb-chain/tss-lib shared `SHA512_256i`"
date: 2023-08-23
primitives: [hash, zkp]
repository: https://github.com/bnb-chain/tss-lib
pr: 256
cve:
  name: CVE-2022-47931
  url: https://nvd.nist.gov/vuln/detail/CVE-2022-47931
source:
  - name: "Verichains TSSHOCK disclosure"
    url: https://verichains.io/tsshock/
---

Fiat-Shamir hashes need to say which execution context they belong to, and they
need an injective encoding of the transcript values. Pre-fix `tss-lib` was
missing both: proof challenges had no caller-supplied session/context tag, and
individual inputs were concatenated without recording their lengths.

Before v2.0.0, `bnb-chain/tss-lib` used a shared `SHA512_256i` helper for proof
challenges across Schnorr, MtA, DLN, and commitment proofs. The helper included
a block-count prefix, but no caller-supplied session/context tag and no
per-input length tag ([source](https://github.com/bnb-chain/tss-lib/blob/v1.3.5/common/hash.go#L53-L84)).

The fix ([PR #256](https://github.com/bnb-chain/tss-lib/pull/256)) introduced
`SHA512_256i_TAGGED`. The tag is supplied by the caller and is typically a
session or party/session context, not a universal proof-type tag; separation
between proof types also depends on the different statement inputs each proof
hashes. The helper hashes the tag into the state and records each input length
before hashing the transcript ([source](https://github.com/bnb-chain/tss-lib/blob/v2.0.0/common/hash.go#L96-L141)):

```go
// FILE: common/hash.go - bnb-chain/tss-lib v2.0.0 (fixed excerpt)
func SHA512_256i_TAGGED(tag []byte, in ...*big.Int) *big.Int {
    tagBz := SHA512_256(tag)
    var data []byte
    state := crypto.SHA512_256.New()
    state.Write(tagBz)
    state.Write(tagBz)

    inLen := len(in)
    inLenBz := make([]byte, 64/8)
    binary.LittleEndian.PutUint64(inLenBz, uint64(inLen))
    ptrs := make([][]byte, inLen)
    for i, n := range in {
        ptrs[i] = n.Bytes()
    }
    data = append(data, inLenBz...)

    for i := range in {
        data = append(data, ptrs[i]...)
        data = append(data, hashInputDelimiter)
        dataLen := make([]byte, 8)
        binary.LittleEndian.PutUint64(dataLen, uint64(len(ptrs[i])))
        data = append(data, dataLen...)
    }

    state.Write(data)
    return new(big.Int).SetBytes(state.Sum(nil))
}
```
