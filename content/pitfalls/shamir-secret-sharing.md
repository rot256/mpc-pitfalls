---
title: "Shamir Secret Sharing"
class: "Cryptographic Primitive"
order: 13
---

- Some implementations let parties choose their own index. By choosing index $0$ or $0 \mod q$, a malicious party receives $f(0)$ as their share, i.e. the secret itself.
  Observe that the index must be reduced modulo the group order *before* the comparison with zero.

### Example

The [vulnerable code](https://github.com/bnb-chain/tss-lib/blob/73560daec7f83d7355107ea9b5e59d16de8765be/crypto/vss/feldman_vss.go#L64-L70) in Binance tss-lib checked for literal zero but not zero modulo the curve order:

```go
// crypto/vss/feldman_vss.go
for i := 0; i < num; i++ {
    if indexes[i].Cmp(big.NewInt(0)) == 0 {
        return nil, nil, fmt.Errorf("party index should not be 0")
    }
    share := evaluatePolynomial(ec, threshold, poly, indexes[i])
    shares[i] = &Share{Threshold: threshold, ID: indexes[i], Share: share}
}
```

An attacker sets their party ID to $q$ (the secp256k1 group order). This passes the `!= 0` check, but since all polynomial arithmetic operates modulo $q$, the evaluation computes $f(q) \equiv f(0)$. The attacker's "share" is the complete secret key.
A secondary issue: if two party IDs are congruent mod $q$, computing Lagrangian coefficients requires dividing by zero.

- The same bug existed in five downstream forks of tss-lib (Keep Network, THORChain, Swingby, Clover Network) and independently in [ZenGo-X curv](https://github.com/ZenGo-X/curv/pull/157) (Rust), which accepted arbitrary `u16` indices including 0.

### References

- Trail of Bits, [Disclosing Shamir's Secret Sharing vulnerabilities](https://blog.trailofbits.com/2021/12/21/disclosing-shamirs-secret-sharing-vulnerabilities-and-announcing-zkdocs/), December 2021.
- [GHSA-gp6j-vx54-5pmf](https://github.com/keep-network/keep-ecdsa/security/advisories/GHSA-gp6j-vx54-5pmf) (Keep Network keep-ecdsa).
