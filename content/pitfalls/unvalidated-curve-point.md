---
title: "Curve Points Not Validated"
class: input-validation
hidden: false
source: "elliptic-curve-groups.md"
primitives: [elliptic-curve, signature]
---

### Curve Points Not Validated

**What can go wrong.** When a party receives a coordinate pair $(X, Y)$ from a peer
and uses it as an elliptic-curve point in any scalar multiplication, two distinct
checks are needed and either one can be skipped:

1. **On-curve check.** $(X, Y)$ must satisfy the curve equation
   $Y^2 \equiv X^3 + aX + b \pmod{p}$. A pair on a *twist* curve $Y^2 = X^3 + b'$ with
   smooth order $n'$ is silently processed by APIs (like Go's
   `elliptic.Curve.ScalarMult`) that depend only on $p$, not on the curve constant $b$.
   The identity point $(0, 0)$ is a second degenerate case in this category and must
   be rejected independently. A subtle refinement: some `IsOnCurve` implementations
   silently reduce $X, Y$ modulo $p$ before checking the curve equation, so a
   canonical-range check $X, Y \in [0, p)$ at the wire boundary is needed to keep the
   wire representation of a point unique (see SRC-2026-573 below).
2. **Subgroup membership.** Even an on-curve point may lie outside the intended
   prime-order subgroup if the curve has cofactor $h > 1$ (Ed25519, Curve25519, BN254,
   BLS12-381). The standard check is $q \cdot P = \mathcal{O}$ for the prime-order
   subgroup of order $q$, or equivalently multiplication by the cofactor with rejection
   of the resulting identity.

**Security implication.** Both failures collapse to the same primitive: the
adversary supplies a point whose order has a small factor $n'$, and every scalar
multiplication $k \cdot P$ by an honest secret $k$ reveals $k \bmod n'$. Brumley,
Barbosa, Page, Vercauteren (2017) demonstrated full X25519 key recovery from ~1000
TLS handshakes using twist points of smooth order $n' \in [2^{10}, 2^{20}]$; the same
vector applies directly to any MPC party that scalar-multiplies an unvalidated peer
point, with full 256-bit key recovery in about $10^4$ signing queries. For threshold
EdDSA specifically (ZenGo's
[Baby Sharks](https://medium.com/zengo/baby-sharks-a3b9ceb4efe0) analysis), a
torsion-injection variant in keygen makes signatures verify with probability $1/8$
per ceremony, either silently denying service or leaking $c \bmod 8$ on every
successful path. In BLS signature aggregation, a non-subgroup public key satisfies
the pairing equation for crafted signatures without knowledge of the corresponding
private key, giving full signature forgery.

**How to avoid.** Validate every externally-supplied point at the wire boundary,
before any scalar multiplication by a secret touches it:

```go
func ValidateCurvePoint(curve elliptic.Curve, X, Y *big.Int) (*ECPoint, error) {
    P, N := curve.Params().P, curve.Params().N
    if X.Sign() < 0 || X.Cmp(P) >= 0 || Y.Sign() < 0 || Y.Cmp(P) >= 0 {
        return nil, errors.New("non-canonical coordinates (outside [0, P))")
    }
    if X.Sign() == 0 && Y.Sign() == 0 {
        return nil, errors.New("point at infinity is not a valid protocol element")
    }
    if !curve.IsOnCurve(X, Y) {
        return nil, errors.New("point is not on the curve")
    }
    // Subgroup check: required whenever cofactor > 1.
    Qx, Qy := curve.ScalarMult(X, Y, N.Bytes())
    if Qx.Sign() != 0 || Qy.Sign() != 0 {
        return nil, errors.New("point outside prime-order subgroup")
    }
    return &ECPoint{curve, X, Y}, nil
}
```

For fresh curve designs, prefer a prime-order curve ($h = 1$, e.g. secp256k1 or P-256),
where the subgroup check is implied by the on-curve check, or the
[Ristretto255](https://ristretto.group)/Decaf abstraction, which exposes only the
prime-order quotient group and makes torsion injection structurally impossible.
