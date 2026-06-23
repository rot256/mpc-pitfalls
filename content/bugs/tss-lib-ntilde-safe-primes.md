---
title: "tss-lib `NTilde` from RSA primes (KS-BTL-F-03)"
date: 2019-10-21
primitives: [rsa, group, paillier, homomorphic-encryption]
repository: https://github.com/bnb-chain/tss-lib
issue: 67
pr: 68
commit: 769ccf744fc844feaa8570589d004def070ddfcd
---

Kudelski Security flagged that pre-fix `bnb-chain/tss-lib` keygen generated the RSA modulus $\tilde N$ in `ecdsa/keygen/round_1.go` via Go's `rsa.GenerateMultiPrimeKey`, which returns ordinary RSA primes, not safe primes. However, the helper that later derives the DLN bases (`common.GetRandomGeneratorOfTheQuadraticResidue`) required $\tilde N$ to be a product of safe primes for its output to land in the prime-order QR subgroup ([source](https://github.com/bnb-chain/tss-lib/blob/a2c27b4/ecdsa/keygen/round_1.go#L64-L74)):

```go
// FILE: ecdsa/keygen/round_1.go — bnb-chain/tss-lib @ a2c27b4 (vulnerable)
// 5-7. generate auxiliary RSA primes for ZKPs later on
go func(ch chan<- *rsa.PrivateKey) {
    pk, err := rsa.GenerateMultiPrimeKey(rand.Reader, 2, RSAModulusLen)
    if err != nil {
        common.Logger.Errorf("RSA generation error: %s", err)
        ch <- nil
    }
    ch <- pk
}(rsaCh)
```

The fix introduced by [PR #68](https://github.com/bnb-chain/tss-lib/pull/68) moved $\tilde N$ generation into a new `ecdsa/keygen/prepare.go` backed by a `GermainSafePrime` generator ([source](https://github.com/bnb-chain/tss-lib/blob/ee93550e/ecdsa/keygen/prepare.go#L53-L72)):

```go
// FILE: ecdsa/keygen/prepare.go — bnb-chain/tss-lib (post-PR #68, fixed)
// 5-7. generate safe primes for ZKPs used later on
go func(ch chan<- []*common.GermainSafePrime) {
    sgps, err := common.GetRandomSafePrimesConcurrent(safePrimeBitLen, 2, timeout, concurrency/2)
    if err != nil {
        ch <- nil
        return
    }
    ch <- sgps
}(sgpCh)
// ...
NTildei, h1i, h2i, err := crypto.GenerateNTildei([2]*big.Int{sgps[0].SafePrime(), sgps[1].SafePrime()})
```

A later commit ([`769ccf744f`](https://github.com/bnb-chain/tss-lib/commit/769ccf744f)) added sanity checks on the generator's output and stored $p = (P-1)/2$, $q = (Q-1)/2$ as witnesses for the DLN proofs over $\tilde N$.