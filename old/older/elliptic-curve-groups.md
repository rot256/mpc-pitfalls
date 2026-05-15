---
title: "Elliptic Curve Groups"
class: "Elliptic Curves"
order: 11
---

Elliptic-curve operations are the computational core of EC-based MPC — threshold
ECDSA, EC-ElGamal commitments, Schnorr-based sigma protocols — and every
scalar-multiplication step assumes the input point is valid, not the identity, and (on
curves with cofactor $h > 1$) lies in the prime-order subgroup. Three implementation
failures break these assumptions: shipping a curve whose cofactor is not cleared on
incoming points; accepting an adversary-supplied pair $(X, Y)$ without checking it is
actually on the curve; and hashing to the curve with a construction that either leaks
timing or is malleable.

### Cofactor not cleared on non-prime-order curves

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

### Adversary-supplied point not validated as on-curve

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

### Insecure hash-to-curve (variable-time / try-and-increment)

**What can go wrong.** Some MPC sub-protocols need to map an arbitrary string to a
curve point — Pedersen-commitment setup, VRF output, hash-based sigma commitments. The
naïve "try-and-increment" construction hashes the input to an $x$-coordinate candidate,
then increments a counter until $y^2 = x^3 + ax + b$ has a square-root solution. The
iteration count depends on whether each candidate $x$ is a quadratic residue — a
property of the input that is observable as a timing side-channel.

**Security implication.** An adversary who can time hash-to-curve calls observes the
number of iterations, which correlates with a data-dependent quadratic-residuosity
test. With enough timing samples the adversary distinguishes inputs; when the input
encodes secret protocol state (a shared key, a nonce seed, a blinding factor), the
timing leak recovers bits of that secret.
[Eprint 2022/759](https://eprint.iacr.org/2022/759.pdf) (Hashimoto et al.) gives the
systematic analysis.

**How to avoid.** Use a standardised constant-time construction. IETF
[RFC 9380](https://www.rfc-editor.org/rfc/rfc9380) specifies `hash_to_curve` as
`hash_to_field` followed by `map_to_curve` (Simplified SWU for Weierstrass curves,
Elligator for Edwards/Montgomery) in constant time with no rejection loop.
Well-tested libraries exist in several languages:
`github.com/bytemare/hash2curve` (Go), `h2c-rust-ref` (Rust), BLST (C / multiple
bindings).

**Example: try-and-increment pseudocode.** The vulnerable pattern:

```go
// INSECURE: variable iteration count leaks timing correlated with input
func HashToCurveInsecure(msg []byte, p *big.Int) (*big.Int, *big.Int) {
    for ctr := byte(0); ; ctr++ {
        digest := sha256.Sum256(append(msg, ctr))
        x := new(big.Int).SetBytes(digest[:])
        x.Mod(x, p)
        rhs := secp256k1RHS(x, p) // x^3 + 7 mod p
        y := new(big.Int).ModSqrt(rhs, p)
        if y != nil {
            return x, y // iteration count is a timing side-channel
        }
    }
}
```

The fix is to replace the loop with a constant-time `hash_to_field` + SWU mapping, as
specified by RFC 9380. No MPC-library CVE is pinned to this specific pattern on this
page yet — but the eprint paper shows it arises naturally in implementations that predate
the IETF standardisation.

<!--
### Commit Timeline

| Date | Repository | Artifact | Description |
|------|-----------|----------|-------------|
| 2017 | Brumley et al. | — | Invalid curve attack on OpenSSL X25519; full key recovery from ~1000 handshakes |
| 2018 | [bnb-chain/tss-lib](https://github.com/bnb-chain/tss-lib) | Initial release | `NewECPoint` with no `IsOnCurve`; all deserialization paths unvalidated |
| ~2019 | [bnb-chain/tss-lib](https://github.com/bnb-chain/tss-lib) | [Issue #46](https://github.com/bnb-chain/tss-lib/issues/46), [Issue #38](https://github.com/bnb-chain/tss-lib/issues/38) | Kudelski audit: `NewECPoint` and `ValidateBasic` have no `IsOnCurve` check |
| ~2019 | [bnb-chain/tss-lib](https://github.com/bnb-chain/tss-lib) | [commit `54a23f1013`](https://github.com/bnb-chain/tss-lib/commit/54a23f1013) | Fix: `NewECPoint` returns error; `isOnCurve` added; all deserialization paths updated |
| 2020 | Shlomovits (ZenGo) | [Baby Sharks](https://medium.com/zengo/baby-sharks-a3b9ceb4efe0) | Torsion point injection in threshold EdDSA; non-deterministic signature acceptance |
| 2022 | Hashimoto et al. | [eprint 2022/759](https://eprint.iacr.org/2022/759.pdf) | Hash-to-curve security analysis; try-and-increment shown to leak timing |
| Dec 2023 | [bnb-chain/tss-lib](https://github.com/bnb-chain/tss-lib) | [Issue #283](https://github.com/bnb-chain/tss-lib/issues/283) | Open: cofactor not cleared in threshold EdDSA; torsion attack concern raised |
| ~2024 | [bnb-chain/tss-lib](https://github.com/bnb-chain/tss-lib) | [commit `685c2af371`](https://github.com/bnb-chain/tss-lib/commit/685c2af371) | Fix SRC-2026-573: reject non-canonical coordinates outside $[0, p)$ |

### Real-World Impact

**tss-lib point-validation window (2018–2019).** Between the initial tss-lib release and the Kudelski audit fix (commit `54a23f1013`), every proof deserialization path accepted adversarially-supplied curve points without validation. Any deployment of tss-lib v1.x that ran keygen or signing with a malicious party during this window was potentially vulnerable to invalid-curve key extraction. The fix required patching ten separate call sites, indicating how pervasive the unchecked constructor was.

**Baby Sharks torsion injection (2020).** Shlomovits demonstrated that the threshold EdDSA cofactor issue produces non-deterministic signatures — a subtle failure that does not crash the protocol but causes honest signatures to be rejected unpredictably. This class of attack is particularly hard to detect in production, because the symptoms (occasional signature rejection) resemble network issues rather than cryptographic failures.
-->
