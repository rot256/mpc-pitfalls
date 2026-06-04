---
title: "bnb-chain/tss-lib shared `SHA512_256i`"
date: 2023-08-23
primitives: [hash, zkp]
repository: https://github.com/bnb-chain/tss-lib
pr: 256
---

Before v2.0.0, `bnb-chain/tss-lib` used a single `SHA512_256i` helper for every proof challenge: Schnorr, MtA, DLN, commitments, with no tag distinguishing which protocol context a hash was produced in ([source](https://github.com/bnb-chain/tss-lib/blob/v1.3.5/common/hash.go#L53-L84)).

The fix ([PR #256](https://github.com/bnb-chain/tss-lib/pull/256)) introduced `SHA512_256i_TAGGED`, which prepends a per-session, per-proof-type tag and length-prefixes every input ([source](https://github.com/bnb-chain/tss-lib/blob/v2.0.0/common/hash.go#L96-L140)):

```go
// common/hash.go — bnb-chain/tss-lib v2.0.0 (fixed)
// SHA512_256i_TAGGED prepends a session-specific tag, providing domain
// separation between different proof types and sessions.
func SHA512_256i_TAGGED(tag []byte, in ...*big.Int) *big.Int {
    data := tag // unique per proof type and session
    for _, v := range in {
        data = append(data, v.Bytes()...)
        data = append(data, hashInputDelimiter)
        dataLen := make([]byte, 8)
        binary.LittleEndian.PutUint64(dataLen, uint64(len(v.Bytes())))
        data = append(data, dataLen...)
    }
    return new(big.Int).SetBytes(crypto.SHA512_256(data))
}
```