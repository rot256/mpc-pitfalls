---
title: "Randomness Has Insufficient Entropy"
class: cryptographic-primitives
hidden: false
order: 6
source: "fiat-shamir.md"
primitives: [randomness, zkp]
---

**What can go wrong.** MPC protocols rely on high-entropy sources for nonces, masks, and blinding factors, and their output must be fresh for each use. A low-entropy source, one that repeats or is predictable, lets an attacker recover any secret that depends on it.

**Security implication.** Any part of the system that relies on a low-entropy source lets even an honest-but-curious adversary brute-force it and recover the secrets, if any, after one or a few observations. In Schnorr signatures, reusing the nonce $r$ across two messages exposes the signing key: with $s_1 = r + c_1 x$ and $s_2 = r + c_2 x$, the key is $x = (s_1 - s_2)(c_1 - c_2)^{-1}$.

**How to avoid.** Draw all protocol randomness from a cryptographically secure RNG with at least a 128-bit security level, and never reuse it across runs. For deterministic nonces, follow the construction in [RFC 6979](https://www.rfc-editor.org/rfc/rfc6979).
