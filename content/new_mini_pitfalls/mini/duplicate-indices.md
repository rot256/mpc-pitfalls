---
title: "Duplicate indices not rejected"
class: "Others"
source: "shamir-secret-sharing.md"
---

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

A malicious party submits $x_j = x_i + q$ for some other party $i$. The raw integer
values differ, so a naïve `!=` check passes; modular reduction makes $x_j \equiv x_i$,
and reconstruction crashes. The fix is the `validateDistinctIndices` pass above,
applied at the protocol's share-ingestion boundary.
