---
title: "Parties' Shares Not Validated as Non-Zero and Distinct"
class: input-validation
source: "shamir-secret-sharing.md"
primitives: [secret-sharing]
---

### Parties' Shares Not Validated as Non-Zero and Distinct

**What can go wrong.** 
Many MPC protocols build upon Shamir secret sharing, a $(t, n)$-threshold scheme that recovers a secret $s = f(0)$ from $t$ shares of a sharing polynomial $f(x) = s + \sum_{i=1}^{t-1} a_i x^i$ over $\mathbb{Z}_q$, with coefficients $a_i$ drawn uniformly at random. Each party $P_i$ holds the share $(i, x_i = f(i))$, and any $t$ parties can reconstruct via $s = \sum_{j} x_j \, l_j(0)$ with Lagrange basis $l_j(0) = \prod_{k, k \ne j} \frac{x_k}{x_k - x_j}$. 
Both the index $i$ and the share $x_i$ live in $\mathbb{Z}_q$, so every implementation must reduce modulo $q$ before using them. Two related failures arise when this reduction is skipped at the input boundary.
*First*, if a party can choose its own index and the implementation rejects only the *integer* $0 \in \mathbb{Z}$, an attacker submitting $i = q$ (or any $k \cdot q$) passes the check while `evaluatePolynomial(q) ≡ evaluatePolynomial(0) = f(0) = secret`, handing it the secret directly.
*Second*, the Lagrange basis denominator $x_k - x_j$ vanishes modulo $q$ whenever any two reconstruction indices coincide mod $q$, whether as the same raw integer (naïve duplicate) or as a malicious $x_k' = x_j + q$ (distinct as `big.Int`, congruent in $\mathbb{Z}_q$). The subsequent modular inverse is undefined.

**Security implication.** A party whose index reduces to $0 \bmod q$ is handed $f(0)$, the shared secret itself: the dealer evaluates the sharing polynomial at the attacker's index and returns the result as normal. In a DKG, where every party deals a contribution, the attacker collects $f(0)$ from each dealer and reconstructs the full private key with no further interaction. The duplicate failure splits into two outcomes. In availability terms, reconstruction crashes with a nil-pointer dereference (Go's `ModInverse` returns `nil` for a non-invertible input) or throws an unrecoverable error, DoS-ing the signing ceremony. In integrity terms, some implementations silently skip the offending term or substitute a default, producing an incorrect reconstruction the caller accepts as valid.

**How to avoid.** Validate indices at the protocol's share-ingestion boundary: reduce each index modulo $q$, reject zero, and verify pairwise distinctness in a single pass.
<!--
```go
func validateIndices(indices []*big.Int, q *big.Int) error {
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

In Rust with an unsigned index type, construct `Scalar::from(index)` and compare against `Scalar::zero()` rather than comparing the integer to `0u16`. Prefer protocol-assigned indices over party-chosen ones whenever feasible.-->

**Example: tss-lib Shamir validation ([Trail of Bits Shamir disclosure](https://blog.trailofbits.com/2021/12/21/disclosing-shamirs-secret-sharing-vulnerabilities-and-announcing-zkdocs/) & [PR #149](https://github.com/bnb-chain/tss-lib/pull/149)).** Both failures appear in `bnb-chain/tss-lib`'s `crypto/vss/feldman_vss.go` and were disclosed together by Trail of Bits in December 2021. They were fixed in a single PR ([`shareid-security`](https://github.com/bnb-chain/tss-lib/pull/149), merge commit [`c26beac`](https://github.com/bnb-chain/tss-lib/commit/c26beac7880cfe0f583eedab419b4641a281de95), December 17 2021).

**Failure 1: zero index mod $q$.** Before the fix, `Create` checked the party index against the integer literal `0` without reducing modulo $q$ first ([source](https://github.com/bnb-chain/tss-lib/blob/73560daec7f83d7355107ea9b5e59d16de8765be/crypto/vss/feldman_vss.go#L64-L70)):

```go
// crypto/vss/feldman_vss.go, bnb-chain/tss-lib (vulnerable, pre-PR #149)
for i := 0; i < num; i++ {
    if indexes[i].Cmp(big.NewInt(0)) == 0 {
        return nil, nil, fmt.Errorf("party index should not be 0")
    }
    // indexes[i] == q passes the check; evaluatePolynomial(q) ≡ f(0) = secret
    share := evaluatePolynomial(ec, threshold, poly, indexes[i])
    shares[i] = &Share{Threshold: threshold, ID: indexes[i], Share: share}
}
```

A malicious party submits index $i = q$. The literal-zero check passes, but `evaluatePolynomial(q) ≡ evaluatePolynomial(0) = f(0) = s`, handing the attacker the shared secret as their share.

**Failure 2: duplicate indices mod $q$.** The same file's `ReConstruct` performs Lagrange interpolation by inverting the index difference $x_j - x_k$ via `ModInverse` ([source](https://github.com/bnb-chain/tss-lib/blob/73560daec7f83d7355107ea9b5e59d16de8765be/crypto/vss/feldman_vss.go#L137-L166)):

```go
// crypto/vss/feldman_vss.go, bnb-chain/tss-lib (Lagrange step in ReConstruct)
sub := modN.Sub(xs[j], share.ID)
subInv := modN.ModInverse(sub)         // nil if sub ≡ 0 mod q
div := modN.Mul(xs[j], subInv)         // nil-pointer dereference
times = modN.Mul(times, div)
```

A malicious party submits $x_j = x_k + q$ for some honest party $k$. The raw integers differ, so any non-modular `!=` check passes; modular reduction makes $x_j \equiv x_k$, `sub` is zero, `ModInverse` returns `nil`, and the next operation panics, DoS-ing the signing ceremony.

**Unified fix: `CheckIndexes`.** PR #149 added a single validation helper called at the start of `Create`. It reduces each index modulo $q$, rejects zero, and rejects duplicates in one pass ([source](https://github.com/bnb-chain/tss-lib/blob/master/crypto/vss/feldman_vss.go#L53-L67)):

```go
// crypto/vss/feldman_vss.go, bnb-chain/tss-lib (fixed, PR #149)
func CheckIndexes(ec elliptic.Curve, indexes []*big.Int) ([]*big.Int, error) {
    visited := make(map[string]struct{})
    for _, v := range indexes {
        vMod := new(big.Int).Mod(v, ec.Params().N)
        if vMod.Cmp(zero) == 0 {
            return nil, errors.New("party index should not be 0")
        }
        vModStr := vMod.String()
        if _, ok := visited[vModStr]; ok {
            return nil, fmt.Errorf("duplicate indexes %s", vModStr)
        }
        visited[vModStr] = struct{}{}
    }
    return indexes, nil
}
```
<!--
**Other affected forks.** The same disclosure prompted parallel patches in [Swingby's tss-lib fork](https://github.com/SwingbyProtocol/tss-lib/commit/3a9d45177ee22e73e4c032d6c48e691d66c899a2) (commit `3a9d451`, "Fixing issue in the Feldman VSS code. Checking indexes modulo the curve order") and [THORChain's tss-lib fork](https://gitlab.com/thorchain/tss/tss-lib/-/commit/e1fed6a07f266d96b5c3d33b9ae29a9adef46edc) (GitLab commit `e1fed6a`). [ZenGo-X/curv PR #157](https://github.com/ZenGo-X/curv/pull/157) addressed only the zero-index leak by changing the index parameter type to `NonZeroU16`; duplicate handling was left to callers. Clover Network's `threshold-crypto` did not respond to disclosure.

The same family of bugs appeared independently in [ZenGo-X/curv](https://github.com/ZenGo-X/curv/pull/157) (Rust), where `u16` party indices silently accepted `0` and the evaluation function did not reject the field-zero scalar before running Horner's method; [PR #157](https://github.com/ZenGo-X/curv/pull/157) added an explicit zero check and narrowed the index type. Trail of Bits' [Shamir Secret Sharing disclosure](https://blog.trailofbits.com/2021/12/21/disclosing-shamirs-secret-sharing-vulnerabilities-and-announcing-zkdocs/) (December 2021) identified the same pattern in five downstream forks of tss-lib (Keep Network, THORChain, Swingby, Clover Network).-->
