---
title: "Fiat-Shamir"
class: "Cryptographic Primitive"
order: 11
---

- The witness domain is not large enough to not allow for computational brute-forcing, i.e. has less than 128 bits of entropy.
- Randomness used does not contain at least 128 bits of entropy.
- The transcript used to generate challenges does not include all required values, including but not limited to the public input and the problem statement ([weak Fiat-Shamir](https://eprint.iacr.org/2020/1052.pdf)).

---

# DRAFT Fiat-Shamir

The Fiat-Shamir heuristic converts an interactive sigma protocol into a non-interactive proof by replacing the verifier's random challenge with a hash of the transcript. For this to be secure in the random-oracle model, the hash input must bind the challenge to the complete proof context: the public statement being proved, all first-message commitments, session and party identifiers, and any other public parameters. Three recurring failures break this binding: omitting the statement (weak Fiat-Shamir); using a soundness parameter too small to prevent brute-force forgery; and omitting intermediate committed values from the hash.

### Example 1: Weak Fiat-Shamir — Statement Not in the Challenge Hash

When a sigma proof's challenge hash omits the public statement (the value being proved about), any valid proof for one statement can be replayed as a proof for a structurally compatible second statement. Aumasson and Shlomovits documented this as "weak Fiat-Shamir" in the context of threshold wallet protocols.

([source](https://eprint.iacr.org/2020/1052.pdf))

```go
// INSECURE: challenge does not include the public key Y (the statement)
func WeakProve(x *big.Int, Y *ECPoint) *Proof {
    r, _ := rand.Int(rand.Reader, q)
    R := ScalarBaseMult(g, r)
    // MISSING: Y.X, Y.Y — challenge is not bound to the statement
    challenge := SHA256(R.X.Bytes(), R.Y.Bytes())
    s := new(big.Int).Add(r, new(big.Int).Mul(challenge, x))
    return &Proof{R: R, S: s}
}

// Verify accepts this proof for any Y — the statement is never checked
func WeakVerify(proof *Proof, Y *ECPoint) bool {
    challenge := SHA256(proof.R.X.Bytes(), proof.R.Y.Bytes())
    lhs := ScalarBaseMult(g, proof.S)
    rhs := ECAdd(proof.R, ScalarMult(Y, challenge))
    return lhs.Equal(rhs) // holds for ANY Y when challenge ignores Y
}
```

**Attack.** Party $P_i$ generates a Schnorr proof $\pi_i = (R, s)$ for public key $Y_i$ in keygen session $A$. In session $B$, an adversary submits $\pi_i$ as a proof for a different key $Y_j$ of its choosing — chosen so that $g^s = R + c \cdot Y_j$ for the same $c$. The verifier accepts, believing the adversary knows $\log Y_j$, which enables a rogue-key substitution.

**Remediation.** Include the complete public statement in every Fiat-Shamir hash:

```go
// SECURE: challenge binds to commitment R AND public key Y AND session context
func StrongProve(sessionId []byte, x *big.Int, Y *ECPoint) *Proof {
    r, _ := rand.Int(rand.Reader, q)
    R := ScalarBaseMult(g, r)
    challenge := SHA256(sessionId, R.X.Bytes(), R.Y.Bytes(), Y.X.Bytes(), Y.Y.Bytes())
    s := new(big.Int).Add(r, new(big.Int).Mul(challenge, x))
    return &Proof{R: R, S: s}
}
```

### Example 2: Insufficient Soundness — Reduced Proof Iteration Count

Some Fiat-Shamir-transformed proofs (DLN non-membership proofs, $\Sigma$-protocols for range proofs) achieve their soundness guarantee only when a specified number of challenge-response iterations are performed. Each iteration provides one bit of soundness; 128 iterations yield $2^{-128}$ forgery probability. Reducing the count below the specification collapses security.

([source](https://github.com/bnb-chain/tss-lib/blob/master/crypto/dlnproof/proof.go))

```go
// crypto/dlnproof/proof.go — bnb-chain/tss-lib
const Iterations = 128 // specification requires 128 rounds for 128-bit soundness

// Multichain's fastMPC fork set this to 1:
// const Iterations = 1  // DO NOT USE — 1-bit soundness, 50% forgery probability
```

**Attack (Verichains TSSHOCK c-guess).** With `Iterations = 1`, the DLN proof has 1-bit soundness: an adversary who does not know the witness can forge a valid proof with probability $1/2$. By submitting multiple signing requests in parallel, the adversary quickly finds one that passes, then extracts the key share using the forged proof. Verichains demonstrated full key extraction from Multichain's fastMPC in a single signing ceremony.

**Remediation.** Do not reduce `Iterations` below the value specified in the cryptographic protocol. For CGGMP21 and GG18/GG20 DLN proofs, the specification requires 128 iterations. If performance is a concern, use the non-interactive compiled version of the proof rather than reducing the round count.

### Example 3: Missing Committed Value in Fiat-Shamir Hash — ProofBobWC

Beyond omitting the statement, individual proof systems can omit intermediate committed values from the challenge hash. When the prover's randomness commitment is absent, an adversary can choose the response $s$ first and compute a consistent $R$ after seeing the challenge — reversing the logical flow of the proof.

([source](https://github.com/bnb-chain/tss-lib/issues/42))

```go
// crypto/mta/proof.go — bnb-chain/tss-lib (pre-PR #43, vulnerable)
// ProofBobWC is Bob's MtA range proof "with check" (GG18 Fig. 10).
// u = g^α is computed but not included in the challenge hash:
eHash = common.SHA512_256i(
    append(pk.AsInts(), X.X(), X.Y(), c1, c2, z, zPrm, t, v, w)...
    // MISSING: u.X(), u.Y() — the EC commitment to the witness randomness
)
```

**Attack.** Without $u = g^\alpha$ in the challenge hash, the adversary fixes a desired response $s$ and solves for a commitment $R$ consistent with $s$ and the challenge — computing the proof backwards. This breaks zero-knowledge and allows forging range proofs without knowing the witness, defeating the MtA check that prevents key extraction.

**Remediation.** PR [#43](https://github.com/bnb-chain/tss-lib/pull/43) (September 11, 2019) added $u$'s coordinates to the hash:

([source](https://github.com/bnb-chain/tss-lib/blob/v1.3.5/crypto/mta/proofs.go))

```go
// Fixed: u (the EC commitment to witness randomness) is now in the hash
eHash = common.SHA512_256i(
    append(pk.AsInts(), X.X(), X.Y(), c1, c2, u.X(), u.Y(), z, zPrm, t, v, w)...
)
```

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
