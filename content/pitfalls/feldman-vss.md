---
title: "Feldman Verified Secret Sharing"
class: "Cryptographic Primitive"
order: 14
---

- If parties do not check the length of the verification values, a malicious party can send a longer vector (which corresponds to a higher-degree polynomial). They can use this to [surreptitiously raise the threshold](https://blog.trailofbits.com/2024/02/20/breaking-the-shared-key-in-threshold-signature-schemes/), preventing honest users from using the key.
- Rogue key attacks: if at least one of the following mitigations is not implemented, a malicious party can fix the shared private key to one that they know after seeing the inputs of all other parties:
    - Force all parties to commit to their inputs before revealing anything
    - Force parties to prove knowledge of their secret contributions (in zero knowledge)

### Example

The [`part2` function](https://github.com/ZcashFoundation/frost/blob/a1350ea18206a812975740207f90fb121883a5b3/frost-core/src/keys/dkg.rs#L395-L446) in ZCash Foundation's FROST checked the number of packages but not the length of each package's commitment vector:

```rust
// frost-core/src/keys/dkg.rs — ZCash Foundation FROST (pre-fix)
pub fn part2<C: Ciphersuite>(
    secret_package: round1::SecretPackage<C>,
    round1_packages: &BTreeMap<Identifier<C>, round1::Package<C>>,
) -> Result<...> {
    if round1_packages.len() != (secret_package.max_signers - 1) as usize {
        return Err(Error::IncorrectNumberOfPackages);
    }
    // No check on commitment vector length per package
    for (sender_identifier, round1_package) in round1_packages {
        // Processes commitments without validating len == min_signers
    }
}
```

The fix (PR #597, commit `e1fb9bc`) added a per-package check: `if package.commitment.0.len() != secret_package.min_signers as usize { return Err(Error::IncorrectNumberOfCommitments); }`.

- Ten implementations across FROST, GG18, and GG20 were affected. Chainflip was the only implementation that had the check.

### References

- Trail of Bits, [Breaking the shared key in threshold signature schemes](https://blog.trailofbits.com/2024/02/20/breaking-the-shared-key-in-threshold-signature-schemes/), February 2024.
- ZCash Foundation FROST, [PR #597](https://github.com/ZcashFoundation/frost/pull/597).

---

# DRAFT Feldman Verified Secret Sharing

Feldman VSS extends Shamir Secret Sharing with public commitments $A_{i,j} = g^{a_{i,j}}$ that allow each participant to verify their received share. The scheme is correct only when receivers validate that: (1) the commitment vector has the expected length; (2) the commitments bind the sender to a specific polynomial and the sender cannot change that polynomial after seeing others' contributions (rogue key / key-cancellation attack); and (3) commitment vectors from one session are never reused in another.

### Example 1: Commitment Vector Length Not Checked — FROST DKG (Trail of Bits 2024)

The `part2` function in ZCash Foundation's FROST implementation checked the number of round-1 packages received but not the length of each package's commitment vector. A vector of length $t + k$ corresponds to a degree-$(t+k-1)$ polynomial, silently raising the reconstruction threshold.

([source](https://github.com/ZcashFoundation/frost/blob/a1350ea18206a812975740207f90fb121883a5b3/frost-core/src/keys/dkg.rs#L395-L446))

```rust
// frost-core/src/keys/dkg.rs — ZCash Foundation FROST (pre-fix)
pub fn part2<C: Ciphersuite>(
    secret_package: round1::SecretPackage<C>,
    round1_packages: &BTreeMap<Identifier<C>, round1::Package<C>>,
) -> Result<(round2::SecretPackage<C>, Vec<round2::Package<C>>)> {
    if round1_packages.len() != (secret_package.max_signers - 1) as usize {
        return Err(Error::IncorrectNumberOfPackages);
    }
    for (sender_identifier, round1_package) in round1_packages {
        // processes commitment vector without validating len == min_signers
        verify_proof_of_knowledge(sender_identifier, round1_package.commitment(), ...)?;
    }
}
```

**Attack.** A malicious party $P_m$ sends a commitment vector of length $t + k$. Honest parties accept it and treat the protocol as threshold-$t$. At reconstruction, $t + k$ shares are required; honest parties hold only $t$-degree shares and the key is permanently irrecoverable. $P_m$ has effectively destroyed the shared key without any on-chain trace.

**Remediation.** After checking the package count, verify each commitment vector length:

([source](https://github.com/ZcashFoundation/frost/pull/597))

```rust
// frost-core/src/keys/dkg.rs — ZCash Foundation FROST (fixed, PR #597)
for (sender_identifier, round1_package) in round1_packages {
    if round1_package.commitment().0.len() != secret_package.min_signers as usize {
        return Err(Error::IncorrectNumberOfCommitments);
    }
    // ...
}
```

### Example 2: Rogue Key Attack — No Proof of Knowledge

In a Feldman VSS-based DKG, each party $P_i$ broadcasts $A_{i,0} = g^{a_{i,0}}$ (commitment to the secret contribution). The shared public key is $Y = \prod_i A_{i,0}$. Without a proof that each party knows the discrete log of $A_{i,0}$, a malicious party waits to see all other commitments, then sets $A_{m,0} = g^{a_m} \cdot (\prod_{i \neq m} A_{i,0})^{-1}$ — making $Y = g^{a_m}$, a key only $P_m$ knows.

([source](https://blog.trailofbits.com/2024/02/20/breaking-the-shared-key-in-threshold-signature-schemes/))

```go
// INSECURE DKG round 1: commitment broadcast without proof of knowledge
type Round1Package struct {
    Commitment []*ECPoint // g^{a_{i,j}} for j = 0..t-1
    // MISSING: proof of knowledge of a_{i,0}
    // Adversary can wait, observe all A_{i,0}, then choose A_{m,0} to cancel them
}
```

**Attack.** Let $Y^* = g^x$ be the adversary's target key. After observing $A_{1,0}, \ldots, A_{n-1,0}$, $P_m$ announces $A_{m,0} = Y^* \cdot (\prod_{i \neq m} A_{i,0})^{-1}$. Multiplying all commitments gives $\prod_i A_{i,0} = Y^*$. The shared key is $Y^*$, controlled entirely by $P_m$.

**Remediation.** Every round-1 package must include either: (a) a Schnorr proof of knowledge of $a_{i,0}$ binding the commitment to the sender's identity and session; or (b) a commitment-before-reveal scheme where each party commits to a hash of its round-1 message before revealing. ZCash Foundation's FROST correctly includes a `proof_of_knowledge` field:

([source](https://github.com/ZcashFoundation/frost/blob/main/frost-core/src/keys/dkg.rs))

```rust
// frost-core/src/keys/dkg.rs — ZCash Foundation FROST (correct approach)
pub struct Package<C: Ciphersuite> {
    pub commitment: VerifiableSecretSharingCommitment<C>,
    pub proof_of_knowledge: Signature<C>, // Schnorr PoK of a_{i,0}
}

pub fn part1<C: Ciphersuite>(...) -> Result<(SecretPackage<C>, Package<C>)> {
    let proof_of_knowledge = compute_proof_of_knowledge(&coefficients[0], identifier, ...);
    Ok((secret_package, Package { commitment, proof_of_knowledge }))
}
```

### Example 3: Stale Commitment Vectors Accepted Across Sessions

Some implementations cache Feldman commitments from a previous DKG run without binding them to the current session. A malicious party can send fresh shares verified against old commitments, breaking the DKG's contribution-binding property.

```go
// INSECURE: commitment cached from a previous run accepted without freshness check
type Party struct {
    CachedCommitments map[PartyID][]*ECPoint // from previous DKG session
}

func (p *Party) verifyShare(sender PartyID, share *big.Int) bool {
    commitments := p.CachedCommitments[sender] // stale — not bound to current session
    return feldmanVerify(share, p.Index, commitments)
}
```

**Attack.** $P_m$ participates honestly in session $A$, generating commitments $\mathbf{A}^{(A)}$ for a polynomial it controls. In session $B$, $P_m$ sends new shares computed from a different polynomial, but honest parties verify them against the cached $\mathbf{A}^{(A)}$ from session $A$. If $P_m$ crafted both polynomials, the shares pass verification while encoding a secret only $P_m$ knows.

**Remediation.** Never cache commitment vectors across protocol sessions. Include the session identifier and round number in every commitment hash, and verify that the session tag in received commitments matches the current session before accepting.

### Commit Timeline

| Date | Repository | Artifact | Description |
|------|-----------|----------|-------------|
| ~2021 | Multiple | Threshold DKG audits | Rogue key attacks documented in GG18/GG20 and FROST DKG variants |
| Feb 2024 | Trail of Bits | [Breaking the shared key](https://blog.trailofbits.com/2024/02/20/breaking-the-shared-key-in-threshold-signature-schemes/) | Commitment vector length attack across 10 implementations; only Chainflip had the check |
| Feb 2024 | [ZcashFoundation/frost](https://github.com/ZcashFoundation/frost) | [PR #597](https://github.com/ZcashFoundation/frost/pull/597) | Fix: per-package commitment vector length check added |

### Real-World Impact

**Ten implementations, one fix (February 2024).** Trail of Bits identified the Feldman commitment-vector-length attack in 10 threshold signature implementations across FROST, GG18, and GG20 variants and found that Chainflip was the only deployment that had independently implemented the correct length check. The coordinated disclosure drove simultaneous patches across the ecosystem. The rogue key attack vector has been known since the original DKG literature; its recurrence across modern implementations underscores that spec-level mitigations ("parties prove knowledge of their contribution") are not reliably translated into implementation-level checks without explicit auditing.
