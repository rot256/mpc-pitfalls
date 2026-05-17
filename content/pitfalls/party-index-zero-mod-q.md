---
title: "Party Index Not Validated as Non-Zero Mod q"
class: input-validation
hidden: true
source: "shamir-secret-sharing.md"
primitives: [secret-sharing]
---

### Party Index Not Validated as Non-Zero Mod q

<!--<div class="pitfall-flags"><span class="flag flag-shared">Shared example with <a href="#non-zero-check-performed-in-the-wrong-domain">Non-Zero Check Performed in the Wrong Domain</a></span></div>-->

**What can go wrong.** Shamir reconstructs the secret as $f(0)$, where $f$ is the
sharing polynomial. If an implementation lets parties choose their own index and
accepts the literal integer `0` as invalid but does not reduce the index modulo the
group order $q$ before the check, an attacker setting their index to $q$ (or any
$k \cdot q$) passes the check while causing `evaluatePolynomial(q) ≡ evaluatePolynomial(0)= f(0) = \text{secret}$`. The same bug shows up when indices are typed as small
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
