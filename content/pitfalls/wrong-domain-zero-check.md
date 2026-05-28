---
title: "Non-Zero Check Performed in the Wrong Domain"
class: input-validation
hidden: true
source: "improper-verification.md"
primitives: [secret-sharing]
---

### Non-Zero Check Performed in the Wrong Domain

<!--<div class="pitfall-flags"><span class="flag flag-shared">Shared example with <a href="#party-index-not-validated-as-non-zero-mod-q">Party Index Not Validated as Non-Zero Mod q</a></span></div>-->

**What can go wrong.** When a received value $x$ must be rejected if it is zero in
$\mathbb{Z}_q^*$, the check must be `x mod q != 0`, not `x != 0` in integer arithmetic. A
value $x = k \cdot q$ for any integer $k$ passes the integer comparison but is zero in the
protocol's arithmetic domain. The same mistake generalizes to any modular or curve-scalar
setting where the wire representation can exceed the modulus without the type system
flagging it.

**Security implication.** A malicious party sends a value that is zero in the protocol's
arithmetic domain but non-zero in the language's integer type. The honest verifier accepts
it, and downstream operations silently collapse: polynomial evaluation at zero returns the
constant term; modular inversion of zero blows up or returns zero; Pedersen commitments
degenerate to trivial openings. In Shamir secret sharing, an attacker who submits $x = q$
as its "index" receives $f(q) \equiv f(0) = \text{secret}$.

**How to avoid.** Reduce received values modulo the protocol's arithmetic domain *before*
the zero check, e.g. `new(big.Int).Mod(x, q).Sign() == 0`. Apply the same discipline to
every $\mathbb{Z}_q^*$ membership test; integer comparisons against the literal `0` are
not sufficient.

**Example: juicebox-sdk allows index 0 on reconstruction ([Issue #6](https://github.com/juicebox-systems/juicebox-sdk/issues/6)).**
In `juicebox-systems/juicebox-sdk`'s Shamir
secret-sharing crate, share creation enforces non-zero indices structurally
(`(1..=count).map(Index)`), but `recover_secret` runs Lagrange interpolation over
whatever indices the caller supplies, with no reconstruction-time check
([source](https://github.com/juicebox-systems/juicebox-sdk/blob/main/rust/secret_sharing/src/lib.rs#L97-L117)):

```rust
// rust/secret_sharing/src/lib.rs — juicebox-systems/juicebox-sdk (vulnerable)
pub fn recover_secret<S: Secret>(shares: &[Share<S>]) -> Result<S, RecoverSecretError> {
    shares
        .iter()
        .enumerate()
        .map(|(i, share)| {
            let others = shares[..i].iter().chain(&shares[i + 1..]);
            let numerator: Scalar = others
                .clone()
                .map(|other_share| other_share.index.as_scalar())
                .product();
            let denominator: Scalar = others
                .map(|other_share| other_share.index.as_scalar() - share.index.as_scalar())
                .product();
            // No check that share.index != 0; an attacker-supplied index 0
            // makes their share's secret dominate the reconstruction.
            ...
        })
        .sum()
}
```

A malicious party submits `Share { index: Index(0), secret: x }` for any chosen `x`, so the recovered secret collapses to the attacker-chosen `x`. The bug is unfixed at the time of writing.
<!--; the underlying
type is `curve25519-dalek::scalar::Scalar`, so the integer-vs-modular distinction does
not apply here.-->
<!--**Example: tss-lib party index `== q`.** In `bnb-chain/tss-lib`, party indices for the
Feldman VSS share assignment were compared against the integer literal `0` only
([source](https://github.com/bnb-chain/tss-lib/blob/73560daec7f83d7355107ea9b5e59d16de8765be/crypto/vss/feldman_vss.go#L64-L70)):

```go
// crypto/vss/feldman_vss.go — bnb-chain/tss-lib (vulnerable)
for i := 0; i < num; i++ {
    if indexes[i].Cmp(big.NewInt(0)) == 0 {
        return nil, nil, fmt.Errorf("party index should not be 0")
    }
    // indexes[i] == q passes the check; evaluatePolynomial(q) ≡ f(0) = secret
    share := evaluatePolynomial(ec, threshold, poly, indexes[i])
}
```

A party that sets its ID to the secp256k1 group order $q$ passes the `!= 0` check, but
polynomial evaluation runs modulo $q$, so the returned "share" is $f(0)$, the shared
secret. See the [Shamir Secret Sharing](../shamir-secret-sharing/) pitfall for the full
writeup and remediation.
-->
