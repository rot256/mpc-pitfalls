---
title: "Feldman Verified Secret Sharing"
class: "Secret Sharing"
order: 14
---

### Commitment vector length not checked (threshold-raise sabotage)

<div class="pitfall-flags"><span class="flag flag-shared">Shared example with <a href="#received-sequence-has-the-wrong-length">Received sequence has the wrong length</a></span></div>

**What can go wrong.** Feldman VSS commits each sharing party to a specific
degree-$(t-1)$ polynomial by broadcasting the vector of coefficient commitments
$(A_{i,0}, A_{i,1}, \dots, A_{i,t-1})$. Receivers must check that the vector is
exactly $t$ entries long. An attacker sending $t + k$ commitments is implicitly
binding to a degree-$(t+k-1)$ polynomial; honest parties that proceed without the
length check will be running a threshold-$(t+k)$ protocol under the belief that it is
threshold-$t$. The implementation does not notice because each individual share still
verifies against the (longer) commitment vector.

**Security implication.** At reconstruction time, $t + k$ shares are required but
honest parties hold only $t$ values. The shared key becomes permanently unrecoverable
— a key-destruction attack with no on-chain trace. The attacker incurs no cost beyond
sending a longer round-1 message. [Trail of Bits' 2024
disclosure](https://blog.trailofbits.com/2024/02/20/breaking-the-shared-key-in-threshold-signature-schemes/)
catalogued this across ten implementations in FROST, GG18, and GG20; only Chainflip had
independently added the per-package length check.

**How to avoid.** After checking the number of incoming packages, verify each
package's commitment vector length against the expected threshold before any of its
elements are used. The check is a single equality — cheap to enforce at the
protocol-entry boundary.

**Example: ZCash Foundation FROST `part2` — Trail of Bits 2024.** The `part2` function
checked the number of round-1 packages received but not the length of each package's
commitment vector
([source](https://github.com/ZcashFoundation/frost/blob/a1350ea18206a812975740207f90fb121883a5b3/frost-core/src/keys/dkg.rs#L395-L446)):

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

[PR #597](https://github.com/ZcashFoundation/frost/pull/597) added the per-package
length check:

```rust
// frost-core/src/keys/dkg.rs — ZCash Foundation FROST (fixed, PR #597)
for (sender_identifier, round1_package) in round1_packages {
    if round1_package.commitment().0.len() != secret_package.min_signers as usize {
        return Err(Error::IncorrectNumberOfCommitments);
    }
    // ...
}
```

### Rogue-key attack: no commit-before-reveal and no proof of knowledge

**What can go wrong.** In a Feldman-based DKG, each party $P_i$ broadcasts
$A_{i,0} = g^{a_{i,0}}$ — the commitment to its secret contribution $a_{i,0}$ — and
the shared public key is $Y = \prod_i A_{i,0}$. If the protocol neither requires
parties to commit to their first-round messages before seeing others' contributions
nor requires each party to prove knowledge of $a_{i,0}$, a malicious party waits to
see all other parties' commitments and then chooses its own $A_{m,0}$ as a function
of theirs. The attacker can thereby force the shared public key to be a key it alone
controls.

**Security implication.** Let $Y^\star = g^x$ be the adversary's target (a key for
which it holds the discrete log $x$). After observing
$A_{1,0}, \dots, A_{n-1,0}$, $P_m$ announces $A_{m,0} = Y^\star \cdot
\left(\prod_{i \ne m} A_{i,0}\right)^{-1}$. Multiplying all commitments yields
$\prod_i A_{i,0} = Y^\star$. The shared "threshold" key is now under $P_m$'s sole
control — reconstruction is not required and the $(t, n)$ threshold property is
vacuous.

**How to avoid.** Either of the following two mitigations is sufficient; most
deployments use both:

- **Commit-before-reveal**: each party first broadcasts a hash commitment to its
  round-1 package, and only reveals the package after every other party's commitment
  has been seen. The attacker cannot choose its $A_{m,0}$ as a function of the
  others because the hash binds it before any other party has opened.
- **Proof of knowledge**: each round-1 package includes a Schnorr proof of knowledge
  of $a_{i,0}$, binding the commitment to the sender's identity and the current
  session. An attacker that chose $A_{m,0}$ adversarially cannot produce a valid
  proof without knowing the discrete log.

**Example: synthetic round-1 package without PoK, FROST reference.** The vulnerable
shape is a commitment broadcast with no accompanying proof:

```go
// INSECURE DKG round 1: commitment broadcast without proof of knowledge
type Round1Package struct {
    Commitment []*ECPoint // g^{a_{i,j}} for j = 0..t-1
    // MISSING: proof of knowledge of a_{i,0}
    // Adversary can wait, observe all A_{i,0}, then choose A_{m,0} to cancel them
}
```

ZCash Foundation's FROST closes this by including a `proof_of_knowledge` field that
pins down $a_{i,0}$ to the sender's identity
([source](https://github.com/ZcashFoundation/frost/blob/main/frost-core/src/keys/dkg.rs)):

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

The rogue-key attack vector has been known since the early DKG literature; its
recurrence across modern implementations — Trail of Bits' 2024 disclosure found both
the length-check and rogue-key failures in multiple libraries at once — underscores
that spec-level mitigations do not reliably translate into implementation-level
checks without explicit auditing.

<!--
### Commit Timeline

| Date | Repository | Artifact | Description |
|------|-----------|----------|-------------|
| ~2021 | Multiple | Threshold DKG audits | Rogue key attacks documented in GG18/GG20 and FROST DKG variants |
| Feb 2024 | Trail of Bits | [Breaking the shared key](https://blog.trailofbits.com/2024/02/20/breaking-the-shared-key-in-threshold-signature-schemes/) | Commitment vector length attack across 10 implementations; only Chainflip had the check |
| Feb 2024 | [ZcashFoundation/frost](https://github.com/ZcashFoundation/frost) | [PR #597](https://github.com/ZcashFoundation/frost/pull/597) | Fix: per-package commitment vector length check added |

### Real-World Impact

**Ten implementations, one fix (February 2024).** Trail of Bits identified the Feldman commitment-vector-length attack in 10 threshold signature implementations across FROST, GG18, and GG20 variants and found that Chainflip was the only deployment that had independently implemented the correct length check. The coordinated disclosure drove simultaneous patches across the ecosystem. The rogue key attack vector has been known since the original DKG literature; its recurrence across modern implementations underscores that spec-level mitigations ("parties prove knowledge of their contribution") are not reliably translated into implementation-level checks without explicit auditing.
-->
