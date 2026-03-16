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
