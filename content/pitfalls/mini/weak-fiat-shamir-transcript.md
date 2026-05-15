---
title: "Challenge Transcript Missing Required Values (Weak Fiat-Shamir)"
class: lack-of-context-binding
source: "fiat-shamir.md"
primitives: [zkp, paillier, homomorphic-encryption]
---

### Challenge Transcript Missing Required Values (Weak Fiat-Shamir)

**What can go wrong.** 
In the Fiat-Shamir transformation, the verifier's challenge is replaced by a hash. Soundness requires that the challenge $c$ be the hash of *every* value the verifier's equation depends on: the public statement, the prover's first-message commitment(s), and any auxiliary values that appear in the verification relation. Missing any of these lets the prover choose the omitted value *after* seeing the challenge, enabling forgery. The [Aumasson–Shlomovits weak-FS analysis](https://eprint.iacr.org/2020/1052.pdf) catalogues several such variants across threshold-wallet implementations.

**Security implication.** Depending on what is missing: (i) missing the public statement makes the proof valid for any statement with the same structural shape (a cross-statement replay); (ii) missing a commitment lets the prover pick a response first and solve for a consistent commitment backwards, producing a proof with no valid witness; (iii) missing a verification-equation input frees the prover to construct a value that satisfies the omitted constraint post hoc. In every case the verifier accepts a proof that no honest prover could have produced.

**How to avoid.** When implementing an FS transform, enumerate every value that appears in the verification equation (public statement, all first-round commitments, all auxiliary public inputs) and hash *all* of them into the challenge. Prepend a constant-length domain-separation tag identifying the specific proof type to prevent cross-proof-type substitutions.

**Example: tss-lib ProofBobWC missing `u` in hash ([Issue #42](https://github.com/bnb-chain/tss-lib/issues/42), [PR #43](https://github.com/bnb-chain/tss-lib/pull/43)).** The MtA "Bob-with-check"
range proof in `bnb-chain/tss-lib` involves a commitment $u = g^\alpha$ to the prover's
randomness. Pre-fix, the FS hash omitted `u`
([source](https://github.com/bnb-chain/tss-lib/issues/42)):

```go
// crypto/mta/proof.go — bnb-chain/tss-lib (pre-PR #43, vulnerable)
// u is computed but NOT included in the challenge hash:
eHash = common.SHA512_256i(
    append(pk.AsInts(), X.X(), X.Y(), c1, c2, z, zPrm, t, v, w)...
    // MISSING: u.X(), u.Y() — the EC commitment to the witness randomness
)
```

Because $u$ is absent, the challenge $e$ is independent of the prover's randomness commitment. A malicious party fixes a desired response, recomputes the challenge on values
of its choosing, and solves for a consistent $u$ after the fact, forging a valid-looking proof without a witness.

The fix ([PR #43](https://github.com/bnb-chain/tss-lib/pull/43), merged September 11, 2019) added `u.X()`, `u.Y()` to the hash input:

```go
// Fixed: u (the EC commitment to witness randomness) is now in the hash
eHash = common.SHA512_256i(
    append(pk.AsInts(), X.X(), X.Y(), c1, c2, u.X(), u.Y(), z, zPrm, t, v, w)...
)
```
