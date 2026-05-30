---
title: "Insufficient Soundness from Reduced Iteration Count"
class: cryptographic-primitives
hidden: false
order: 3
source: "fiat-shamir.md"
primitives: [zkp]
---


**What can go wrong.** Some FS-transformed proofs — notably the DLN non-membership proof
used in GG18/GG20/CGGMP21, and certain $\Sigma$-protocols for range arguments — achieve
their soundness guarantee only through many parallel challenge-response iterations. Each
iteration contributes roughly one bit of soundness: 128 iterations yield $2^{-128}$
forgery probability; 64 iterations yield $2^{-64}$; 1 iteration yields $2^{-1}$ — a 50%
forgery probability per attempt.

**Security implication.** An adversary who can submit candidate proofs to the verifier
finds a forgery in expected time $2^{k-1}$ where $k$ is the iteration count. With
$k = 1$, a single attempt suffices. Because DLN proofs on Paillier parameters gate
access to the honest party's key share, a successful forgery translates directly into
share extraction in one signing ceremony.

**How to avoid.** Do not reduce `Iterations` (or the equivalent soundness parameter) below
the value mandated by the cryptographic specification. For CGGMP21 / GG18 / GG20 DLN
proofs, the specification requires **128 iterations**. If performance is the motivation,
use a non-interactive compiled proof that folds parallel iterations into a single hash
rather than cutting the round count.

**Example: Multichain fastMPC DLN iterations = 1 (TSSHOCK).** Multichain's fastMPC fork
of tss-lib changed the DLN iteration constant:

```go
// crypto/dlnproof/proof.go — bnb-chain/tss-lib (spec-compliant)
const Iterations = 128 // 128 rounds for 128-bit soundness

// Multichain fastMPC fork set:
const Iterations = 1   // 1-bit soundness — 50% forgery probability per attempt
```

Verichains demonstrated the [**TSSHOCK** c-guess
attack](https://blog.verichains.io/p/tsshock-critical-vulnerabilities): with
`Iterations = 1`, the adversary submits parallel signing requests, forges a valid DLN
proof on roughly half of them, and uses the forged proof to extract a signing key share.
Full key extraction from Multichain's fastMPC was confirmed in a single signing
ceremony; Multichain's bridge was drained of over \$130M in July 2023.
