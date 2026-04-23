---
title: "Fiat-Shamir"
class: "Fiat-Shamir & ZK Proofs"
order: 4
---

The Fiat-Shamir transform converts an interactive sigma protocol (prover commits,
verifier sends a random challenge, prover responds) into a non-interactive proof by
replacing the verifier's challenge with a hash of the protocol transcript. In MPC this
shows up everywhere: proofs of knowledge for secret key shares, range proofs in MtA, DLN
proofs on Paillier parameters, Schnorr proofs of honest behaviour.

Two overlapping classes of failure recur. **Intrinsic FS failures** — the transform
itself applied incorrectly: challenge hash missing required inputs, witness or randomness
entropy too low, soundness-amplification round count cut below spec. **Execution-binding
failures** — the transform applied correctly, but the resulting proof not tied to the
session, prover identity, or protocol context in which it was produced. The
execution-binding case is local to the proof construction itself and can bite even in a
single-session deployment, provided the adversary can observe and replay individual proof
messages; it is distinct from the UC session-ID concern, which governs the overall
protocol transcript. The mini-pitfalls below cover both classes.

### Witness domain has insufficient entropy

<div class="pitfall-flags"><span class="flag flag-tbd">TBD example</span></div>

**What can go wrong.** A Fiat-Shamir proof of knowledge is only meaningful if the witness
the prover claims to know is drawn from a domain the adversary cannot brute-force
offline. If the witness space has fewer than ~128 bits of entropy — a short PIN, a
human-chosen passphrase, a timestamp-derived value — an adversary can enumerate all
candidate witnesses, compute the FS proof for each, and submit one that matches the
transcript. The soundness of FS assumes the witness is computationally inaccessible; it
does not make a guessable witness unguessable.

**Security implication.** The adversary produces a valid proof without ever having had
access to the honest party's witness. In an MPC ceremony this lets a corrupt participant
masquerade as if it contributed a valid secret at keygen, or authenticate to a role it
does not hold. Because the forged proof is a genuine FS artifact, no verifier-side check
detects it.

**How to avoid.** Sample every witness from a space with at least 128 bits of
min-entropy. For human-chosen inputs, stretch entropy with a password-based KDF
(argon2id, scrypt) before the secret enters the protocol. For protocol-derived
witnesses, do not use small counters, session indices, or short bit-strings as the
value being proven.

**Example.** *TBD.* This is a structural entropy requirement rather than a
specific-CVE pitfall; it is typically caught in audit rather than in a single patch.

### Randomness has insufficient entropy

<div class="pitfall-flags"><span class="flag flag-tbd">TBD example</span></div>

**What can go wrong.** Sigma protocols require the prover to sample fresh commitment
randomness $r$ for each run. If that randomness has fewer than ~128 bits of entropy —
or is reused across proofs, or is derived from an observable source — the secret
witness can be extracted algebraically from one or a few proofs. This is the same class
as the classical ECDSA nonce-reuse attack, generalised to any FS-based sigma proof.

**Security implication.** A passive observer who can infer or predict the prover's
randomness recovers the secret after observing one or a few proofs. For threshold
signing, a single signer with a weak RNG leaks its share across signatures. For DLN or
range proofs on Paillier parameters, weak randomness can leak the Paillier prime
factorisation. No protocol-level misbehaviour is required; the RNG weakness alone is
enough.

**How to avoid.** Draw all protocol randomness from a cryptographically secure RNG that
provides at least 128 bits of entropy per call. If using a deterministic FS variant
(nonce derived from the secret and the message), follow the construction in
[RFC 6979](https://www.rfc-editor.org/rfc/rfc6979); never reuse commitment randomness
across proofs.

**Example.** *TBD.* RNG weaknesses are common audit findings but no MPC-specific CVE is
pinned to this page yet.

### Challenge transcript missing required values (weak Fiat-Shamir)

**What can go wrong.** For the FS transform to be sound, the challenge $e$ must be the
output of a hash over *every* value the verifier's equation depends on: the public
statement, the prover's first-message commitment(s), and any auxiliary values that
appear in the verification relation. Missing any of these lets the prover choose the
omitted value *after* seeing the challenge — reversing the logical order of the sigma
protocol and enabling forgery. The
[Aumasson–Shlomovits weak-FS analysis](https://eprint.iacr.org/2020/1052.pdf) catalogues
several such variants across threshold-wallet implementations.

**Security implication.** Depending on what is missing: (i) missing the public statement
makes the proof valid for any statement with the same structural shape, a cross-statement
replay; (ii) missing a commitment lets the prover pick a response first and solve for a
consistent commitment backwards, producing a proof with no valid witness at all;
(iii) missing a verification-equation input frees the prover to construct a value that
satisfies the omitted constraint post hoc. In every case the verifier accepts a proof
that no honest prover could have produced.

**How to avoid.** When implementing an FS transform, enumerate every value that appears
in the verification equation — public statement, all first-round commitments, all
auxiliary public inputs — and hash *all* of them into the challenge. Prepend a
constant-length domain-separation tag identifying the specific proof type to prevent
cross-proof-type substitutions.

**Example: tss-lib ProofBobWC missing `u` in hash (Issue #42).** The MtA "Bob-with-check"
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

Because $u$ is absent, the challenge $e$ is independent of the prover's randomness
commitment. An adversary fixes a desired response, recomputes the challenge on values
of its choosing, and solves for a consistent $u$ after the fact — forging a valid-looking
proof without a witness. This defeats the MtA check that prevents key-share extraction
in threshold ECDSA.

The fix ([PR #43](https://github.com/bnb-chain/tss-lib/pull/43), merged September 11,
2019) added `u.X()`, `u.Y()` to the hash input:

```go
// Fixed: u (the EC commitment to witness randomness) is now in the hash
eHash = common.SHA512_256i(
    append(pk.AsInts(), X.X(), X.Y(), c1, c2, u.X(), u.Y(), z, zPrm, t, v, w)...
)
```

### Insufficient soundness from reduced iteration count

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

<!--
### Commit Timeline

| Date | Repository | Artifact | Description |
|------|-----------|----------|-------------|
| Sep 9, 2019 | [bnb-chain/tss-lib](https://github.com/bnb-chain/tss-lib) | [Issue #42](https://github.com/bnb-chain/tss-lib/issues/42) | ProofBobWC Fiat-Shamir hash missing committed value $u = g^\alpha$ |
| Sep 11, 2019 | [bnb-chain/tss-lib](https://github.com/bnb-chain/tss-lib) | [PR #43](https://github.com/bnb-chain/tss-lib/pull/43) | Fix: add $u$ coordinates to MtA proof hash |
| 2020 | Aumasson & Shlomovits | [eprint 2020/1052](https://eprint.iacr.org/2020/1052.pdf) | Weak Fiat-Shamir documented; missing statement enables proof reuse across sessions |
| Jul 2023 | Verichains | [TSSHOCK](https://blog.verichains.io/p/tsshock-critical-vulnerabilities) | DLN iteration count 1 exploited; 1-bit soundness enables c-guess key extraction |

### Real-World Impact

**Multichain TSSHOCK (\$130M+, July 2023).** Reducing the DLN proof from 128 iterations to 1 dropped Fiat-Shamir soundness to a single bit. Verichains' c-guess attack exploited this to extract a key share in one signing ceremony, enabling the \$130M+ bridge drain. This is a direct consequence of the second failure mode above — insufficient soundness — caused by modifying a proof-iteration constant without understanding its security impact.

**tss-lib ProofBobWC (September 2019).** The missing $u$ commitment in the MtA range proof was caught and patched two days after being reported (Issue #42 → PR #43). While no exploitation is documented, the window between deployment of early tss-lib versions and the fix represents a period during which any implementation using `ProofBobWC` in an adversarial setting was vulnerable to forged range proofs.
-->
