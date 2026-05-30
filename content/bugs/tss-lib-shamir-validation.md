---
title: "tss-lib Shamir validation"
category: input-validation
subcategory: "Parties' Shares Not Validated as Non-Zero and Distinct"
date: 2021-12-17
primitives: [secret-sharing]
repository: https://github.com/bnb-chain/tss-lib
commit: c26beac7880cfe0f583eedab419b4641a281de95
pr: 149
source:
  - name: "Trail of Bits Shamir disclosure"
    url: https://blog.trailofbits.com/2021/12/21/disclosing-shamirs-secret-sharing-vulnerabilities-and-announcing-zkdocs/
hidden: false
---

Both failures appear in `bnb-chain/tss-lib`'s `crypto/vss/feldman_vss.go` and were disclosed together by Trail of Bits. They were fixed in a single PR ([`shareid-security`](https://github.com/bnb-chain/tss-lib/pull/149), merge commit [`c26beac`](https://github.com/bnb-chain/tss-lib/commit/c26beac7880cfe0f583eedab419b4641a281de95)).

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
