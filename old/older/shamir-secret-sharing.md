---
title: "Shamir Secret Sharing"
class: "Secret Sharing"
order: 13
---

Shamir Secret Sharing and its verifiable extension Feldman VSS underpin distributed
key generation and signing in virtually every threshold protocol. Shamir assumes party
indices are **non-zero, pairwise distinct** elements of $\mathbb{Z}_q^*$; Feldman
layers on public commitments so participants can verify received shares match a
specific degree-$(t-1)$ polynomial, and requires those commitments to bind the sender
to a single polynomial before contributions are revealed. Implementation failures at
either layer either hand the shared key to a single adversary (literal-zero-index and
rogue-key attacks) or destroy it outright (threshold-raise sabotage).

### Party index not validated as non-zero mod q

<!--<div class="pitfall-flags"><span class="flag flag-shared">Shared example with <a href="#non-zero-check-performed-in-the-wrong-domain">Non-zero check performed in the wrong domain</a></span></div>-->

**What can go wrong.** Shamir reconstructs the secret as $f(0)$, where $f$ is the
sharing polynomial. If an implementation lets parties choose their own index and
accepts the literal integer `0` as invalid but does not reduce the index modulo the
group order $q$ before the check, an attacker setting their index to $q$ (or any
$k \cdot q$) passes the check while causing `evaluatePolynomial(q) ≡ evaluatePolynomial(0)
= f(0) = \text{secret}$. The same bug shows up when indices are typed as small
unsigned integers (e.g., `u16`): the integer `0` itself is a valid value of the type,
and if the zero check is written against the type's default the implementation
accepts it.

**Security implication.** The attacker receives the shared secret as their "share".
Because the check passes, honest parties send the share unmodified, and the attacker
now holds the full private key. No interaction with the other parties is required
beyond a normal sharing ceremony in which the attacker's index is their own chosen
value.

**How to avoid.** Reduce the index modulo $q$ *before* comparing to zero, and use a
type that cannot silently carry the zero value. In Go:
`if new(big.Int).Mod(idx, q).Sign() == 0 { return error }`. In Rust with an unsigned
index type, construct `Scalar::from(index)` and compare against `Scalar::zero()` rather
than comparing the integer to `0u16`. Prefer protocol-assigned indices over
party-chosen ones whenever feasible.

**Example: tss-lib literal-zero check missing mod-$q$ normalization.** The vulnerable
code in tss-lib compared the party index against the integer literal `0`
([source](https://github.com/bnb-chain/tss-lib/blob/73560daec7f83d7355107ea9b5e59d16de8765be/crypto/vss/feldman_vss.go#L64-L70)):

```go
// crypto/vss/feldman_vss.go — bnb-chain/tss-lib (vulnerable)
for i := 0; i < num; i++ {
    if indexes[i].Cmp(big.NewInt(0)) == 0 {
        return nil, nil, fmt.Errorf("party index should not be 0")
    }
    // indexes[i] == q passes the check; evaluatePolynomial(q) ≡ f(0) = secret
    share := evaluatePolynomial(ec, threshold, poly, indexes[i])
    shares[i] = &Share{Threshold: threshold, ID: indexes[i], Share: share}
}
```

The fix reduces modulo $q$ before the zero check:

```go
reduced := new(big.Int).Mod(indexes[i], ec.Params().N)
if reduced.Sign() == 0 {
    return nil, nil, fmt.Errorf("party index is 0 mod q")
}
```

The same bug appeared independently in [ZenGo-X/curv](https://github.com/ZenGo-X/curv/pull/157)
(Rust), where `u16` party indices silently accepted `0` and the evaluation function did
not reject the field-zero scalar before running Horner's method. [PR #157](https://github.com/ZenGo-X/curv/pull/157)
added an explicit zero check and narrowed the index type. Trail of Bits' [Shamir
Secret Sharing disclosure](https://blog.trailofbits.com/2021/12/21/disclosing-shamirs-secret-sharing-vulnerabilities-and-announcing-zkdocs/)
(December 2021) identified the same pattern in five downstream forks of tss-lib (Keep
Network, THORChain, Swingby, Clover Network).

### Duplicate indices not rejected

**What can go wrong.** Lagrange interpolation reconstructs $f(0)$ from $t$ shares via
coefficients of the form $\prod_{j \ne i} \frac{-x_j}{x_i - x_j}$. The denominator
$x_i - x_j$ is zero modulo $q$ whenever any two reconstruction indices are equal
modulo $q$ — either the same integer (naïve duplicate) or congruent modulo $q$ (an
index submitted as $x_j = x_i + q$, which differs as a `big.Int` but is the same
element of $\mathbb{Z}_q$). The subsequent modular inverse is undefined.

**Security implication.** Two distinct failures. In availability terms: reconstruction
crashes with a nil-pointer dereference (Go's `ModInverse` returns `nil` for a
non-invertible input) or throws an unrecoverable error, DoS-ing the signing ceremony.
In integrity terms: some implementations silently skip the offending term or substitute
a default, producing an incorrect reconstruction the caller accepts as valid.

**How to avoid.** After reducing all indices modulo $q$, verify they are pairwise
distinct before running Lagrange interpolation. A single pass through a set suffices:

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

Combining non-zero and pairwise-distinct checks in one helper catches both mini-pitfalls
at a single protocol-entry point.

**Example: tss-lib Lagrange denominator.** tss-lib's `lagrangeCoefficient` computes the
product of `(idx - indexes[i]) mod q` across other parties; with a duplicate pair, one
factor is zero and `ModInverse` returns `nil`
([source](https://github.com/bnb-chain/tss-lib/blob/73560daec7f83d7355107ea9b5e59d16de8765be/crypto/vss/feldman_vss.go)):

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

A malicious party submits $x_j = x_i + q$ for some other party $i$. The integer
values differ, so a naïve `!=` check passes; modular reduction makes $x_j \equiv x_i$,
and reconstruction crashes. The fix is the `validateDistinctIndices` pass above,
applied at the protocol's share-ingestion boundary.

<!--
### Commit Timeline

| Date | Repository | Artifact | Description |
|------|-----------|----------|-------------|
| ~2018 | [bnb-chain/tss-lib](https://github.com/bnb-chain/tss-lib) | Initial release | Index checked against literal 0, not $0 \bmod q$; no duplicate index check |
| ~2020 | [ZenGo-X/curv](https://github.com/ZenGo-X/curv) | Pre-fix | `u16` party indices; index $= 0$ results in $f(0) =$ secret |
| Dec 2021 | Trail of Bits | [Shamir's Secret Sharing vulnerabilities](https://blog.trailofbits.com/2021/12/21/disclosing-shamirs-secret-sharing-vulnerabilities-and-announcing-zkdocs/) | Index-$q$ and duplicate-index attacks disclosed across tss-lib, five forks, and ZenGo-X/curv |
| Dec 2021 | [ZenGo-X/curv](https://github.com/ZenGo-X/curv) | [PR #157](https://github.com/ZenGo-X/curv/pull/157) | Fix: explicit zero-index check added |
| Dec 2021 | [keep-network/keep-ecdsa](https://github.com/keep-network/keep-ecdsa) | [GHSA-gp6j-vx54-5pmf](https://github.com/keep-network/keep-ecdsa/security/advisories/GHSA-gp6j-vx54-5pmf) | Coordinated disclosure for Keep Network fork |

### Real-World Impact

Trail of Bits' December 2021 disclosure affected tss-lib and five downstream forks (Keep Network, THORChain, Swingby, Clover Network), plus the independent ZenGo-X/curv library. No live exploit was publicly confirmed, but every deployment before the patch was vulnerable to a single malicious party receiving the full shared secret by choosing their own index as $q$ or $0$.
-->
