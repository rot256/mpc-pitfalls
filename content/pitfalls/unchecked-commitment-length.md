---
title: "Commitment Vector Length Not Checked (Threshold-Raise Sabotage)"
class: input-validation
hidden: true
source: "feldman-vss.md"
primitives: [secret-sharing, commitment]
---

### Commitment Vector Length Not Checked (Threshold-Raise Sabotage)

<div class="pitfall-flags"><span class="flag flag-shared">Shared example with <a href="#received-sequence-has-the-wrong-length">Received Sequence Has the Wrong Length</a></span></div>

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
cataloged this across ten implementations in FROST, GG18, and GG20; only Chainflip had
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
