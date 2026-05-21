---
title: "tss-lib `ProofBobWC` missing `u` in hash"
category: lack-of-context-binding
subcategory: "Challenge Transcript Missing Required Values (Weak Fiat-Shamir)"
date: 2019-09-11
primitives: [zkp]
repository: https://github.com/bnb-chain/tss-lib
issue: 42
pr: 43
hidden: false
---

The MtA "Bob-with-check"
range proof in `bnb-chain/tss-lib` involves a commitment $u = g^\alpha$ to the prover's
randomness. Pre-fix, the FS hash omitted `u`
([source](https://github.com/bnb-chain/tss-lib/issues/42)):

```go
// crypto/mta/proof.go — bnb-chain/tss-lib (pre-PR #43, vulnerable)
// u is computed but NOT included in the challenge hash:
eHash = common.SHA512_256i(
    append(pk.AsInts(), X.X(), X.Y(), c1, c2, z, zPrm, t, v, w)...
    // MISSING: u.X(), u.Y() — the EC commitment to the witness randomness
)
```

Because $u$ is absent, the challenge $e$ is independent of the prover's randomness commitment. A malicious party fixes a desired response, recomputes the challenge on values
of its choosing, and solves for a consistent $u$ after the fact, forging a valid-looking proof without a witness.

The fix ([PR #43](https://github.com/bnb-chain/tss-lib/pull/43), merged September 11, 2019) added `u.X()`, `u.Y()` to the hash input:

```go
// Fixed: u (the EC commitment to witness randomness) is now in the hash
eHash = common.SHA512_256i(
    append(pk.AsInts(), X.X(), X.Y(), c1, c2, u.X(), u.Y(), z, zPrm, t, v, w)...
)
```
