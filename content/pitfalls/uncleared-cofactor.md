---
title: "Cofactor Not Cleared on Non-Prime-Order Curves"
class: input-validation
hidden: true
source: "elliptic-curve-groups.md"
primitives: [elliptic-curve, signature]
---

### Cofactor Not Cleared on Non-Prime-Order Curves

**What can go wrong.** Edwards and Montgomery curves used in MPC (Ed25519, Curve25519)
have cofactor $h = 8$: the full curve group has order $8\ell$ for large prime $\ell$,
and the 8-element torsion subgroup includes the identity and seven low-order points.
If a protocol accepts a received point without multiplying by $h$ to strip torsion — or
without using a construction like Ristretto255 that hides the torsion quotient — a
malicious party can inject a torsion component into a shared public key, share, or
nonce commitment and either leak information about secret scalars or create
non-deterministic verification behaviour.

**Security implication.** A malicious party in threshold EdDSA sends a key share
$X_m = x_m \cdot B + T$ where $T$ is a torsion point of order 8. The joint public key
$Y = \sum X_i$ acquires the extra torsion component $T$. Subsequent signatures
$s \cdot B = R + c \cdot Y$ then hold only when $c \cdot T = \mathcal{O}$ — i.e., when
$c \equiv 0 \pmod 8$ — so the signature verifies probabilistically (1 in 8), causing
either silent denial-of-service (honest signatures rejected most of the time) or
channel-like leakage of $c \bmod 8$ per ceremony. Smaller cofactors on other curves give
analogous but smaller-bit leaks.

**How to avoid.** Multiply every externally-supplied point by the cofactor $h$ and
reject if the result is the identity (the input was a pure torsion point). For fresh
curve designs, prefer a prime-order curve ($h = 1$, e.g. secp256k1 or P-256) or the
[Ristretto255](https://ristretto.group)/Decaf abstraction, which exposes only the
prime-order quotient group and makes torsion injection structurally impossible.

```go
// ClearCofactor multiplies P by h; returns error if P was a torsion point.
func ClearCofactor(curve EdwardsCurve, P *EdwardsPoint) (*EdwardsPoint, error) {
    cleared := curve.ScalarMult(P, curve.Cofactor())
    if cleared.IsIdentity() {
        return nil, errors.New("received torsion point — small-subgroup attack")
    }
    return cleared, nil
}
```

**Example: threshold EdDSA "Baby Sharks".** ZenGo's
[Baby Sharks analysis](https://medium.com/zengo/baby-sharks-a3b9ceb4efe0) demonstrated
the torsion-injection attack against threshold EdDSA implementations that accept
round-1 commitments without cofactor clearing. tss-lib Issue
[#283](https://github.com/bnb-chain/tss-lib/issues/283) (December 2023) raised this as
an open concern for the library's threshold EdDSA path:

```go
// Conceptual threshold-EdDSA keygen without cofactor clearing
// Malicious party sends X_m = x_m*B + T where T is a torsion point (8*T = O).
// Honest parties compute joint key Y = Σ X_i = (Σ x_i)*B + T.
// Signing produces s such that s*B = R + c*Y = R + c*(X + T).
// Verification s*B == R + c*Y succeeds only when c*T == O, i.e. c ≡ 0 mod 8.
// Probability of signature acceptance per ceremony: 1/8.
```
