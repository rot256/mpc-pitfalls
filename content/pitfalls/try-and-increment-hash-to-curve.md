---
title: "Variable-Time Hash-to-Curve (Try-and-Increment)"
class: cryptographic-primitives
hidden: true
order: 9
source: "elliptic-curve-groups.md"
primitives: [hash, elliptic-curve]
---
<!--I think this pitfall is not relevant to our current taxonomy, as it happens in a very special case of MPC protocols that require a non-conventional threat model, which assumes server/cloud aid that an adversary can rely on. The servers would not be part of the protocol, but rather extra computational resources for the party. The adversary can exploit that to extract side-channel information. This differs significantly from the typical case, where the parties only run the protocol between themselves. Anyway, these kinds of timing side-channel attacks would require a different, specific threat model, which is not very common. So I am not sure this pitfall is really relevant in the context of MPC as they are used today.

A related reference is: *Time is money, friend! Timing Side-channel Attack against Garbled Circuit Constructions*, Cryptology ePrint Archive, Paper 2023/001, 2023. [https://eprint.iacr.org/2023/001](https://eprint.iacr.org/2023/001)
-->

**What can go wrong.** MPC protocols like threshold OPRF/PAKE (password), blind signing (blinded message), and some threshold VRFs (private state) hash secret inputs to a curve point. The naïve "try-and-increment" construction hashes the input to an $x$-coordinate candidate, then increments a counter until $y^2 = x^3 + ax + b$ has a square-root solution. The iteration count depends on whether each candidate $x$ is a quadratic residue, a property of the input observable as a timing side-channel.

**Security implication.** An adversary timing hash-to-curve calls learns the iteration count of each invocation. With enough samples, the iteration pattern recovers bits of the hashed input, leaking the secret of the affected sub-protocol. [Dragonblood (Vanhoef-Ronen, S&P 2020)](https://eprint.iacr.org/2019/383) demonstrated the attack against WPA3-SAE's Dragonfly "Hunting and Pecking" hash-to-curve, recovering user passwords from real implementations.

**How to avoid.** Use a standardized constant-time construction. IETF
[RFC 9380](https://www.rfc-editor.org/rfc/rfc9380) specifies `hash_to_curve` as `hash_to_field` followed by `map_to_curve`, running in constant time with no rejection loop. Tested implementations include `github.com/bytemare/hash2curve` (Go), `h2c-rust-ref` (Rust), and BLST (C with bindings to several languages). More recently, [SwiftEC (Chávez-Saab et al., 2022)](https://eprint.iacr.org/2022/759) achieves indifferentiable hashing in a single map evaluation.
<!--
No MPC implementation bug is pinned to this pitfall.-->
