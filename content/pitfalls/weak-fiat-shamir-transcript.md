---
title: "Challenge Transcript Missing Required Values (Weak Fiat-Shamir)"
class: lack-of-context-binding
hidden: false
source: "fiat-shamir.md"
primitives: [zkp, paillier, homomorphic-encryption]
---

### Challenge Transcript Missing Required Values (Weak Fiat-Shamir)

**What can go wrong.** 
In the Fiat-Shamir transformation, the verifier's challenge is replaced by a hash. Soundness requires that the challenge $c$ be the hash of *every* value the verifier's equation depends on: the public statement, the prover's first-message commitment(s), and any auxiliary values that appear in the verification relation. Missing any of these lets the prover choose the omitted value *after* seeing the challenge, enabling forgery. The [Aumasson–Shlomovits weak-FS analysis](https://eprint.iacr.org/2020/1052.pdf) catalogues several such variants across threshold-wallet implementations.

**Security implication.** Depending on what is missing: (i) missing the public statement makes the proof valid for any statement with the same structural shape (a cross-statement replay); (ii) missing a commitment lets the prover pick a response first and solve for a consistent commitment backwards, producing a proof with no valid witness; (iii) missing a verification-equation input frees the prover to construct a value that satisfies the omitted constraint post hoc. In every case the verifier accepts a proof that no honest prover could have produced.

**How to avoid.** When implementing an FS transform, enumerate every value that appears in the verification equation (public statement, all first-round commitments, all auxiliary public inputs) and hash *all* of them into the challenge. Prepend a constant-length domain-separation tag identifying the specific proof type to prevent cross-proof-type substitutions.
