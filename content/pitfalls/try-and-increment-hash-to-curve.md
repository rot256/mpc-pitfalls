---
title: "Insecure Hash-to-Curve (Variable-Time / Try-and-Increment)"
class: others
hidden: true
source: "elliptic-curve-groups.md"
primitives: [hash, elliptic-curve]
---

### Insecure Hash-to-Curve (Variable-Time / Try-and-Increment)

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
