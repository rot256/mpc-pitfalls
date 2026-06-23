---
title: "tss-lib `ProofBobWC` missing `u` in hash"
date: 2019-09-11
primitives: [zkp]
repository: https://github.com/bnb-chain/tss-lib
issue: 42
pr: 43
---

The MtA "Bob-with-check"
range proof in `bnb-chain/tss-lib` involves a commitment $u = g^\alpha$ to the prover's
randomness. Pre-fix, the FS hash omitted `u`
([source](https://github.com/bnb-chain/tss-lib/issues/42)):

<!--more-->

```go
// crypto/mta/proofs.go — bnb-chain/tss-lib (pre-PR #43, vulnerable)
// u is computed but NOT included in the challenge hash:
eHash = common.SHA512_256i(
    append(pk.AsInts(), X.X(), X.Y(), c1, c2, z, zPrm, t, v, w)...
    // MISSING: u.X(), u.Y() — the EC commitment to the witness randomness
)
```

Because $u$ is absent, the challenge $e$ is independent of the prover's randomness commitment, so the proof is malleable: a malicious party can fix a desired response, recompute the challenge on values
of its choosing, and in principle solve for a consistent $u$ after the fact, breaking the proof's soundness.

The fix ([PR #43](https://github.com/bnb-chain/tss-lib/pull/43)) added `u.X()`, `u.Y()` to the hash input:

```go
// Fixed: u (the EC commitment to witness randomness) is now in the hash
eHash = common.SHA512_256i(
    append(pk.AsInts(), X.X(), X.Y(), c1, c2, u.X(), u.Y(), z, zPrm, t, v, w)...
)
```
