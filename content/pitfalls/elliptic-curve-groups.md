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
