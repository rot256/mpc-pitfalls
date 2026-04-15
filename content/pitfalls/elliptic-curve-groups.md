---
title: "Elliptic Curve Groups"
class: "Cryptographic Primitive"
order: 8
---

- Not ensuring that the co-factor of the curve is 1 _or_ all base elements are validated to live in the large subgroup.
- Anything selected by a potentially malicious party (e.g. client) is not validated to be a valid point on the curve (_not_ infinity) _and_ potentially living in the large subgroup in case of co-factor different from 1.
- Not using a curve hashing algorithm for hashing to the curve. That is, hashing an element to a random $x$ coordinate and computing the $y$ coordinate is likely not going to be secure. See [this paper](https://eprint.iacr.org/2022/759.pdf) for details.

---

# DRAFT Elliptic Curve Groups

Elliptic-curve operations are the computational core of EC-based MPC — threshold ECDSA, EC-ElGamal commitments, and Schnorr-based sigma protocols all assume that every curve point is valid, non-identity, and (when the curve has cofactor $h > 1$) lies in the prime-order subgroup. Three failure modes allow an adversary to break this assumption: submitting an off-curve point (invalid curve attack); submitting a low-order torsion point on a curve with $h > 1$ (small-subgroup attack); and using a non-constant-time hash-to-curve construction that leaks timing.

### Example 1: Off-Curve Points — tss-lib `NewECPointNoCurveCheck`

tss-lib exposes two constructors for curve points. `NewECPoint` calls Go's `IsOnCurve` before returning; `NewECPointNoCurveCheck` skips validation entirely and is used in proof-deserialization paths where the caller is assumed to have already verified the point.

([source](https://github.com/bnb-chain/tss-lib/blob/master/crypto/ecpoint.go))

```go
// crypto/ecpoint.go — bnb-chain/tss-lib
func NewECPoint(curve elliptic.Curve, X, Y *big.Int) (*ECPoint, error) {
    if !curve.IsOnCurve(X, Y) {
        return nil, fmt.Errorf("point is not on the curve")
    }
    return &ECPoint{curve, X, Y}, nil
}

// NewECPointNoCurveCheck skips IsOnCurve — used in several proof paths
func NewECPointNoCurveCheck(curve elliptic.Curve, X, Y *big.Int) *ECPoint {
    return &ECPoint{curve, X, Y}
}
```

**Attack (Invalid Curve Attack).** An adversary sends $(X', Y')$ that satisfies a *twist* of secp256k1 — a curve $Y^2 = X^3 + b'$ with a different constant $b'$ and a smooth order $n'$. Go's `ScalarMult` uses only $X$, $Y$, and the prime $p$, not $b$, so the computation proceeds on the twist. After $O(\log k / \log n')$ queries the attacker reconstructs the private scalar $k$ via CRT. For secp256k1 twists, $n'$ values in the range $2^{10}$–$2^{20}$ are achievable, so full 256-bit key recovery requires on the order of $10^4$ queries.

**Remediation.** Always use `NewECPoint` when deserialising curve points from external parties. Also explicitly reject the identity point: in Go's `elliptic` package, infinity is $(0, 0)$.

```go
func ValidateCurvePoint(curve elliptic.Curve, X, Y *big.Int) (*ECPoint, error) {
    if X.Sign() == 0 && Y.Sign() == 0 {
        return nil, errors.New("point at infinity is not a valid protocol element")
    }
    if !curve.IsOnCurve(X, Y) {
        return nil, errors.New("point is not on the curve")
    }
    return &ECPoint{curve, X, Y}, nil
}
```

### Example 2: Cofactor Not Cleared — Small-Subgroup Attack on Edwards Curves

Edwards and Montgomery curves (Ed25519, Curve25519) have cofactor $h = 8$. The torsion subgroup has 8 elements including the identity. If a party accepts a torsion point $T$ (with $8 \cdot T = \mathcal{O}$) as a peer's public key and computes $k \cdot T$, the result cycles through only 8 values — leaking $k \bmod 8$ (the three least-significant bits of the scalar).

**Attack.** An adversary sends one of the eight torsion points as its public key. The honest party's response encodes $k \bmod 8$. After gathering responses for different torsion bases, the adversary reconstructs the low bits of the scalar. Iterated across re-keying sessions, this enables more complete extraction.

**Remediation.** On curves with $h > 1$, perform cofactor clearing: multiply any externally-supplied point by $h$ and reject the result if it is the identity (the input was a torsion point). Alternatively, use a prime-order curve ($h = 1$, such as secp256k1 or P-256) or the Ristretto255/Decaf abstraction, which exposes only the prime-order quotient group.

([source](https://eprint.iacr.org/2022/759.pdf))

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

### Example 3: Insecure Hash-to-Curve (Try-and-Increment)

Some MPC sub-protocols require hashing an arbitrary string to a curve point — for Pedersen-commitment setup, VRF outputs, or hash-based sigma commitments. The naïve try-and-increment approach hashes the input to an $x$-coordinate candidate and increments a counter until $y^2 = x^3 + ax + b$ has a solution. The number of iterations is data-dependent and observable.

([source](https://eprint.iacr.org/2022/759.pdf))

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

**Attack.** An adversary who can time hash-to-curve calls observes the number of iterations, which depends on whether each candidate $x$ is a quadratic residue. With enough timing samples the adversary can distinguish inputs and, when the hash-to-curve input encodes secret data, recover bits of the secret.

**Remediation.** Implement [IETF RFC 9380](https://www.rfc-editor.org/rfc/rfc9380) `hash_to_curve`, which uses `hash_to_field` followed by `map_to_curve` (Simplified SWU or Elligator) in constant time with no rejection loop. Libraries: `github.com/bytemare/hash2curve` (Go), `h2c-rust-ref` (Rust).

### Commit Timeline

| Date | Repository | Artifact | Description |
|------|-----------|----------|-------------|
| 2017 | Brumley et al. | — | Invalid curve attack on OpenSSL X25519; full key recovery from ~1000 handshakes |
| 2018 | [bnb-chain/tss-lib](https://github.com/bnb-chain/tss-lib) | Initial release | `NewECPointNoCurveCheck` introduced; used in proof deserialization |
| 2022 | Hashimoto et al. | [eprint 2022/759](https://eprint.iacr.org/2022/759.pdf) | Systematic analysis of hash-to-curve security; try-and-increment shown to leak timing |
| 2023 | IETF | [RFC 9380](https://www.rfc-editor.org/rfc/rfc9380) | Standardises constant-time `hash_to_curve` for common curves |

### Real-World Impact

**Invalid curve attacks on TLS (2017).** Brumley et al. demonstrated complete recovery of an X25519 private key from a server that omitted curve-point validation, using approximately 1000 TLS handshakes. The same vector applies directly to MPC keygen and signing rounds where a corrupted party can supply off-curve points: any honest party that calls `NewECPointNoCurveCheck` on untrusted input without a prior `IsOnCurve` check is potentially vulnerable. Threshold wallets relying on tss-lib should audit every deserialization path to ensure the validated constructor is used consistently.

---

# DRAFT Elliptic Curve Groups (Revised)

Elliptic-curve operations are the computational core of EC-based MPC. Three concrete implementation failures were found in tss-lib and related libraries: the original `NewECPoint` constructor had no `IsOnCurve` check and no error return; a later hardening patch found that non-canonical coordinates (with $X \geq p$) silently passed `IsOnCurve` due to field-arithmetic reduction; and threshold EdDSA implementations failed to reject torsion-subgroup points on curves with cofactor $h > 1$.

### Example 1: `NewECPoint` Without IsOnCurve or Error Return (Issue #46)

The original `NewECPoint` in tss-lib returned a point unconditionally — no curve check, no error return. `ValidateBasic` checked only for non-nil coordinates. Issue #46 (Kudelski Security audit) documented this as allowing any $(X, Y)$ pair to be used as a curve point in proof deserialization and signing rounds.

([source](https://github.com/bnb-chain/tss-lib/issues/46))

```go
// crypto/ecpoint.go — bnb-chain/tss-lib (vulnerable, pre-commit 54a23f1013)
func NewECPoint(curve elliptic.Curve, X, Y *big.Int) *ECPoint {
    return &ECPoint{curve, [2]*big.Int{X, Y}} // no IsOnCurve, no error
}

// ValidateBasic was also broken — no curve check
func (p *ECPoint) ValidateBasic() bool {
    return p != nil && len(p.coords) == 2 && p.coords[0] != nil && p.coords[1] != nil
    // passes for any (X, Y) pair regardless of curve membership
}
```

**Attack (Invalid Curve Attack).** An adversary sends $(X', Y')$ satisfying a *twist* of secp256k1 with smooth order $n'$. Go's `ScalarMult` uses only $X$, $Y$, and the field prime $p$ — not the curve constant $b$ — so computation proceeds on the twist. After $O(\log k / \log n')$ queries the attacker reconstructs the private scalar $k$ via CRT. For secp256k1 twists, orders in the range $2^{10}$–$2^{20}$ are achievable, requiring on the order of $10^4$ signing queries for full 256-bit key recovery.

**Remediation.** Commit [`54a23f1013`](https://github.com/bnb-chain/tss-lib/commit/54a23f1013) added `IsOnCurve` to both the constructor and `ValidateBasic`, and changed the constructor signature to return an error:

([source](https://github.com/bnb-chain/tss-lib/commit/54a23f1013))

```go
// crypto/ecpoint.go — bnb-chain/tss-lib (fixed)
func NewECPoint(curve elliptic.Curve, X, Y *big.Int) (*ECPoint, error) {
    if !isOnCurve(curve, X, Y) {
        return nil, fmt.Errorf("NewECPoint: the given point is not on the elliptic curve")
    }
    return &ECPoint{curve, [2]*big.Int{X, Y}}, nil
}

func isOnCurve(c elliptic.Curve, x, y *big.Int) bool {
    if x == nil || y == nil {
        return false
    }
    return c.IsOnCurve(x, y)
}

func (p *ECPoint) ValidateBasic() bool {
    return p != nil && p.coords[0] != nil && p.coords[1] != nil && p.IsOnCurve()
}
```

The same commit patched all deserialization call sites: `crypto/mta/proofs.go`, `crypto/schnorr/schnorr_proof.go`, `crypto/vss/feldman_vss.go`, `ecdsa/keygen/round_3.go`, and five signing rounds.

### Example 2: Non-Canonical Coordinates Bypass IsOnCurve (SRC-2026-573)

After the Example 1 fix, a subtler issue remained: `isOnCurve` called `c.IsOnCurve(x, y)` without first checking that $x, y \in [0, p)$. The `btcec/v2` library's field arithmetic silently reduces coordinates modulo $p$, so a point with $X = p + x_\text{valid}$ (where $x_\text{valid}$ is a valid x-coordinate) passes `IsOnCurve` — because `btcec` computes $X \bmod p = x_\text{valid}$. Two different `*big.Int` values thus represent "the same" curve point, breaking unique point representation.

([source](https://github.com/bnb-chain/tss-lib/commit/685c2af371))

```go
// crypto/ecpoint.go — bnb-chain/tss-lib (vulnerable, post-54a23f1013)
func isOnCurve(c elliptic.Curve, x, y *big.Int) bool {
    if x == nil || y == nil {
        return false
    }
    return c.IsOnCurve(x, y) // no range check: X = P + x_valid passes silently
}
```

**Attack.** An adversary sends $X' = p + x_\text{valid}$ for a valid $x_\text{valid}$. `IsOnCurve` returns `true` (field arithmetic reduces $X'$ mod $p$). Two parties that receive $X'$ and normalise it differently (one stores $X'$, another stores $x_\text{valid}$) compute with inconsistent views of "the same" point. In Pedersen commitments or Schnorr proofs, this non-canonical representation can produce different hashes for structurally equal values, breaking binding or verification consistency.

**Remediation.** Commit [`685c2af371`](https://github.com/bnb-chain/tss-lib/commit/685c2af371) (SRC-2026-573) added a range check before calling `IsOnCurve`:

([source](https://github.com/bnb-chain/tss-lib/commit/685c2af371))

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

### Example 3: Torsion Point Injection in Threshold EdDSA — "Baby Sharks"

Curve25519 / Ed25519 have cofactor $h = 8$: the full curve group $E(\mathbb{F}_p)$ has order $8\ell$ where $\ell$ is a large prime. The torsion subgroup has 8 elements. In threshold EdDSA, if a party sends a key share $X_i = x_i \cdot B + T$ where $T$ is a torsion point, the joint public key acquires an extra torsion component. Standard EdDSA implementations verify signatures against the joint key, but the torsion component causes the verification equation to hold only probabilistically — creating a split view where some verifiers accept and others reject.

([source](https://medium.com/zengo/baby-sharks-a3b9ceb4efe0))

```go
// Threshold EdDSA keygen — tss-lib (conceptual, no cofactor clearing)
// An adversary sends X_i = x_i*B + T where T is a torsion point (8*T = O).
// Honest parties compute joint key Y = Σ X_i = (Σ x_i)*B + T.
// Signing produces s such that s*B = R + c*Y = R + c*(X + T).
// Verification: s*B == R + c*Y succeeds only when c*T == O, i.e. c ≡ 0 mod 8.
// Probability: 1/8 per signature — causing non-deterministic accept/reject.
```

**Attack.** The malicious party $P_m$ sends $X_m = x_m \cdot B + T$ for a torsion point $T$ of order 8. The honest verifier accepts signatures with probability $1/8$ (when the challenge scalar $c \equiv 0 \bmod 8$). This creates a denial-of-service: threshold signatures produced by honest parties are valid but most verifiers reject them. Alternatively, $P_m$ learns $c \bmod 8$ from observing which signing ceremonies succeed, leaking 3 bits of the challenge per ceremony.

**Remediation.** Multiply every received key share by the cofactor $h = 8$ and reject the result if it is the identity (the input was a torsion point). tss-lib GitHub Issue [#283](https://github.com/bnb-chain/tss-lib/issues/283) (December 2023) raised this as an open concern for the threshold EdDSA implementation. Alternatively, use Ristretto255, which exposes only the prime-order quotient group and makes torsion injection structurally impossible.

### Commit Timeline

| Date | Repository | Artifact | Description |
|------|-----------|----------|-------------|
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
