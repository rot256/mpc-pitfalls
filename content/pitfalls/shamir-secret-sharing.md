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

---

# DRAFT Shamir Secret Sharing

Shamir Secret Sharing underlies the distributed key generation and signing rounds of virtually every threshold protocol. The security proof assumes that party indices are non-zero, pairwise distinct elements of $\mathbb{Z}_q^*$. Three implementation failures violate this assumption: checking for literal zero rather than zero modulo the group order; accepting indices from an unsigned integer type that permits zero; and failing to reject duplicate indices, which causes division by zero in Lagrange interpolation.

### Example 1: Literal Zero Check Misses $q \bmod q = 0$ — bnb-chain/tss-lib

The vulnerable code in tss-lib checked the party index against the integer literal `0` instead of checking `index mod q == 0`. An attacker sets their index to $q$ (the secp256k1 group order), which passes the integer check but evaluates to $f(0)$ — the secret itself.

([source](https://github.com/bnb-chain/tss-lib/blob/73560daec7f83d7355107ea9b5e59d16de8765be/crypto/vss/feldman_vss.go#L64-L70))

```go
// crypto/vss/feldman_vss.go — bnb-chain/tss-lib (vulnerable)
for i := 0; i < num; i++ {
    if indexes[i].Cmp(big.NewInt(0)) == 0 {
        return nil, nil, fmt.Errorf("party index should not be 0")
    }
    // indexes[i] == q passes the check above; evaluatePolynomial(q) ≡ f(0) = secret
    share := evaluatePolynomial(ec, threshold, poly, indexes[i])
    shares[i] = &Share{Threshold: threshold, ID: indexes[i], Share: share}
}
```

**Attack.** The attacker sets their party ID to $q$. Since all polynomial arithmetic operates modulo $q$, `evaluatePolynomial(q) ≡ evaluatePolynomial(0) = f(0)`, which is the secret key. A secondary issue: two party IDs congruent mod $q$ cause a zero denominator in Lagrange interpolation (see Example 3).

**Remediation.** Reduce the index modulo $q$ before comparison:

```go
for i := 0; i < num; i++ {
    reduced := new(big.Int).Mod(indexes[i], ec.Params().N)
    if reduced.Sign() == 0 {
        return nil, nil, fmt.Errorf("party index is 0 mod q")
    }
    share := evaluatePolynomial(ec, threshold, poly, indexes[i])
    shares[i] = &Share{Threshold: threshold, ID: indexes[i], Share: share}
}
```

### Example 2: u16 Index Permits Literal Zero — ZenGo-X/curv (Rust)

The same party-index-zero issue appeared independently in ZenGo-X's `curv` library, which is used across multiple GG18/GG20 threshold wallet implementations. The `ShamirSecretSharing` struct accepted party indices as `u16` values; the evaluation function did not reject index 0.

([source](https://github.com/ZenGo-X/curv/pull/157))

```rust
// curv/src/secret_sharing/shamir.rs — ZenGo-X/curv (pre-fix)
pub fn evaluate_polynomial(coefficients: &[Scalar<E>], index_fe: &Scalar<E>) -> Scalar<E> {
    // index_fe constructed from a u16; if u16 == 0, Scalar<E> is the field zero
    // Horner evaluation at zero returns coefficients[0] == the secret
    coefficients.iter().rev().fold(Scalar::zero(), |acc, c| {
        acc * index_fe + c
    })
}
```

**Remediation.** [PR #157](https://github.com/ZenGo-X/curv/pull/157) added an explicit zero check before evaluation: if `index_fe == Scalar::zero()` return an error. Additionally, the index type was narrowed to prevent caller confusion about whether `0` is a valid sentinel.

### Example 3: Duplicate Indices Cause Division by Zero in Lagrange Interpolation

Lagrange interpolation requires all $t$ reconstruction indices to be pairwise distinct modulo $q$. The Lagrange coefficient for party $i$ includes the term $\frac{1}{x_i - x_j}$ for each $j \neq i$. If $x_i \equiv x_j \pmod{q}$ for any pair, the denominator is zero modulo $q$ and `ModInverse` returns `nil`.

([source](https://github.com/bnb-chain/tss-lib/blob/73560daec7f83d7355107ea9b5e59d16de8765be/crypto/vss/feldman_vss.go))

```go
// crypto/vss/feldman_vss.go — bnb-chain/tss-lib (no duplicate check)
func lagrangeCoefficient(indexes []*big.Int, i int, q *big.Int) *big.Int {
    num := big.NewInt(1)
    den := big.NewInt(1)
    for j, idx := range indexes {
        if j == i { continue }
        diff := new(big.Int).Sub(idx, indexes[i])
        diff.Mod(diff, q)
        den.Mul(den, diff) // diff == 0 mod q if indexes[i] ≡ idx (mod q)
    }
    // ModInverse returns nil when den ≡ 0 mod q → nil dereference
    return num.Mul(num, new(big.Int).ModInverse(den, q))
}
```

**Attack.** A party submits index $x_j = x_i + q$ for some other party $i$. The integer values differ, so an `!=` check passes; but $x_j \equiv x_i \pmod{q}$. At reconstruction, the Lagrange denominator is zero, causing a nil-pointer dereference that crashes the reconstruction party (availability attack) or produces an incorrect output (integrity attack).

**Remediation.** After reducing all indices modulo $q$, verify they are pairwise distinct and non-zero:

```go
func validateDistinctIndices(indices []*big.Int, q *big.Int) error {
    seen := make(map[string]bool)
    for _, idx := range indices {
        reduced := new(big.Int).Mod(idx, q)
        if reduced.Sign() == 0 {
            return errors.New("index is 0 mod q")
        }
        key := reduced.String()
        if seen[key] {
            return errors.New("duplicate index mod q")
        }
        seen[key] = true
    }
    return nil
}
```

### Commit Timeline

| Date | Repository | Artifact | Description |
|------|-----------|----------|-------------|
| ~2018 | [bnb-chain/tss-lib](https://github.com/bnb-chain/tss-lib) | Initial release | Index checked against literal 0, not $0 \bmod q$; no duplicate index check |
| ~2020 | [ZenGo-X/curv](https://github.com/ZenGo-X/curv) | Pre-fix | `u16` party indices; index $= 0$ results in $f(0) =$ secret |
| Dec 2021 | Trail of Bits | [Shamir's Secret Sharing vulnerabilities](https://blog.trailofbits.com/2021/12/21/disclosing-shamirs-secret-sharing-vulnerabilities-and-announcing-zkdocs/) | Index-$q$ and duplicate-index attacks disclosed across tss-lib, five forks, and ZenGo-X/curv |
| Dec 2021 | [ZenGo-X/curv](https://github.com/ZenGo-X/curv) | [PR #157](https://github.com/ZenGo-X/curv/pull/157) | Fix: explicit zero-index check added |
| Dec 2021 | [keep-network/keep-ecdsa](https://github.com/keep-network/keep-ecdsa) | [GHSA-gp6j-vx54-5pmf](https://github.com/keep-network/keep-ecdsa/security/advisories/GHSA-gp6j-vx54-5pmf) | Coordinated disclosure for Keep Network fork |

### Real-World Impact

**Keep Network, THORChain, Swingby, Clover Network (December 2021).** Trail of Bits' coordinated disclosure revealed that five direct forks of tss-lib all inherited the party-index-zero vulnerability independently. In each case the fix was a one-line change — reduce the index modulo $q$ before comparison. The disclosure drove a wave of emergency patches across the BNB Chain ecosystem. Trail of Bits' zkDocs initiative grew from this disclosure, providing auditor-readable specifications of common cryptographic primitives to prevent re-discovery of the same class of bugs.
