---
title: "Adversary-Supplied Point Not Validated as On-Curve"
class: input-validation
hidden: true
source: "elliptic-curve-groups.md"
primitives: [elliptic-curve]
---

### Adversary-Supplied Point Not Validated as On-Curve

**What can go wrong.** When a party receives $(X, Y)$ from a peer and treats it as a
curve point, it must verify that the pair actually satisfies the curve equation before
using it as input to any scalar multiplication. Go's `elliptic.Curve.ScalarMult` uses
only $X$, $Y$, and the field prime $p$ — not the curve constant $b$ — so a pair that
satisfies a *twist* curve $Y^2 = X^3 + b'$ (with smooth order $n'$) is happily processed
as if it were a secp256k1 point. The identity $(0, 0)$ is a second degenerate case that
trivially bypasses discrete-log security and must be rejected independently.

**Security implication.** The invalid-curve attack (Brumley et al., 2017): an adversary
sends $(X', Y')$ on a twist with smooth order $n' \in [2^{10}, 2^{20}]$. Each scalar
multiplication $k \cdot (X', Y')$ returns a value whose low bits depend on
$k \bmod n'$. After $O(\log k / \log n')$ queries the adversary reconstructs $k$ via
CRT — full 256-bit key recovery in about $10^4$ signing queries. Brumley et al.
demonstrated complete X25519 private-key recovery from ~1000 TLS handshakes; the same
vector lands directly on any MPC party that scalar-multiplies an unvalidated peer
point.

**How to avoid.** Validate every externally-supplied $(X, Y)$ at the wire boundary.
Require $X, Y \in [0, p)$ (canonical representation), run `IsOnCurve(X, Y)`, and
explicitly reject the identity point:

```go
func ValidateCurvePoint(curve elliptic.Curve, X, Y *big.Int) (*ECPoint, error) {
    P := curve.Params().P
    if X.Sign() < 0 || X.Cmp(P) >= 0 || Y.Sign() < 0 || Y.Cmp(P) >= 0 {
        return nil, errors.New("non-canonical coordinates (outside [0, P))")
    }
    if X.Sign() == 0 && Y.Sign() == 0 {
        return nil, errors.New("point at infinity is not a valid protocol element")
    }
    if !curve.IsOnCurve(X, Y) {
        return nil, errors.New("point is not on the curve")
    }
    return &ECPoint{curve, X, Y}, nil
}
```

Combine this with the cofactor-clearing step above on non-prime-order curves.

**Example: tss-lib `NewECPoint` without `IsOnCurve` (Issue #46), refined by SRC-2026-573.**
The original tss-lib constructor returned a point unconditionally — no curve check, no
error return — and `ValidateBasic` only checked for non-nil coordinates
([source](https://github.com/bnb-chain/tss-lib/issues/46)):

```go
// crypto/ecpoint.go — bnb-chain/tss-lib (vulnerable, pre-commit 54a23f1013)
func NewECPoint(curve elliptic.Curve, X, Y *big.Int) *ECPoint {
    return &ECPoint{curve, [2]*big.Int{X, Y}} // no IsOnCurve, no error
}

func (p *ECPoint) ValidateBasic() bool {
    return p != nil && len(p.coords) == 2 && p.coords[0] != nil && p.coords[1] != nil
    // passes for any (X, Y) pair regardless of curve membership
}
```

Commit [`54a23f1013`](https://github.com/bnb-chain/tss-lib/commit/54a23f1013) (Kudelski
audit fix) added `IsOnCurve` to the constructor and `ValidateBasic` and changed
`NewECPoint` to return an error. Ten deserialization call sites were patched at the
same time (`crypto/mta/proofs.go`, `crypto/schnorr/schnorr_proof.go`,
`crypto/vss/feldman_vss.go`, `ecdsa/keygen/round_3.go`, and five signing rounds).

A later, subtler variant — SRC-2026-573 — found that `IsOnCurve(X, Y)` in
`btcec/v2` silently reduces $X, Y$ modulo the field prime $P$ before checking the
curve equation, so $X' = P + X$ (for any valid $X$) passes. Two wire representations
of "the same" point coexist, breaking protocols that hash the raw coordinates as
commitment inputs. [Commit `685c2af371`](https://github.com/bnb-chain/tss-lib/commit/685c2af371)
added an explicit range check before `IsOnCurve`:

```go
// crypto/ecpoint.go — bnb-chain/tss-lib (fixed, SRC-2026-573)
func isOnCurve(c elliptic.Curve, x, y *big.Int) bool {
    if x == nil || y == nil {
        return false
    }
    P := c.Params().P
    if x.Sign() < 0 || x.Cmp(P) >= 0 || y.Sign() < 0 || y.Cmp(P) >= 0 {
        return false // reject non-canonical coordinates outside [0, P)
    }
    return c.IsOnCurve(x, y)
}
```

Both are instances of the same pre-Sinsoillier concern: an adversary-supplied point
reaches the cryptographic core without the library having confirmed it is actually on
the curve in its canonical form.
