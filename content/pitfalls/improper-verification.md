---
title: "Improper Verification of Received Messages"
class: "Protocol"
order: 1
---

In MPC protocols, parties exchange mathematical objects such as:

- 'an element from $\mathbb{Z}_q^*$',
- 'a commitment to the coefficients of a degree $t-1$ polynomial'
- 'a list of zero-knowledge proofs'.

In MPC implementations, parties exchange bitstrings over a network, and they need to verify that the received
bitstring corresponds to a valid mathematical object of the expected type. Each of the following issues is commonly
found in MPC implementations, affecting confidentiality, integrity, or availability:

- **The received value is not a valid element**:
    When receiving an element from $\mathbb{Z}_q^*$ or a similar group/ring/field,
    the receiver needs to check that it's non-zero. Additionally, when the element is supposed to generate a non-trivial subgroup, the receiver also needs to check that it's not 1 (or some other invalid value that does not generate the correct subgroup).
- **The received sequence of values is not the correct length**:
    - When receiving the commitments to the coefficients of a degree $t-1$ polynomial during Feldman VSS, the receiver needs to check that the length of the committed coefficient vector is equal to $t$, lest the threshold becomes higher than intended.
    - When receiving a list of zero-knowledge proofs, the receiver needs to verify that the list is not empty. Iterating over an empty list often results in accepting the proofs, as an empty list contains no incorrect proofs.

### Examples

### Example 1: Empty Proof List Passes Vacuously

When a protocol round expects a list of zero-knowledge proofs — one per party, or one per commitment coefficient — an empty list must be rejected explicitly. A `for range` loop over an empty slice executes zero iterations and returns no errors, which is indistinguishable from a loop over a list where every proof passed.

```go
// INSECURE: zero proofs = zero errors = accepted
func verifyCommitmentProofs(proofs []ZKProof) error {
    for _, proof := range proofs {
        if err := proof.Verify(); err != nil {
            return err
        }
    }
    return nil // returns nil even when len(proofs) == 0
}
```

**Attack.** A malicious party sends an empty proof list `[]` when the protocol expects $n-1$ proofs. The verifier iterates zero times, returns `nil`, and proceeds as if all proofs were valid. The adversary's commitments are accepted without proof, allowing it to set arbitrarily biased contribution values in a DKG or signing protocol.

**Remediation.** Check that the length of the received proof list matches the expected count before verification:

```go
func verifyCommitmentProofs(proofs []ZKProof, expected int) error {
    if len(proofs) != expected {
        return fmt.Errorf("expected %d proofs, got %d", expected, len(proofs))
    }
    for _, proof := range proofs {
        if err := proof.Verify(); err != nil {
            return err
        }
    }
    return nil
}
```

### Example 2: Non-Zero Check in the Wrong Domain — tss-lib Party Indices

When receiving a value that must be non-zero in $\mathbb{Z}_q^*$, the check `x != 0` must be performed as `x mod q != 0`, not as `x != 0` in integer arithmetic. A value $x = q$ (or $x = kq$) passes the integer check but is $0 \bmod q$.

([source](https://github.com/bnb-chain/tss-lib/blob/73560daec7f83d7355107ea9b5e59d16de8765be/crypto/vss/feldman_vss.go#L64-L70))

```go
// crypto/vss/feldman_vss.go — bnb-chain/tss-lib (vulnerable)
for i := 0; i < num; i++ {
    if indexes[i].Cmp(big.NewInt(0)) == 0 {
        return nil, nil, fmt.Errorf("party index should not be 0")
    }
    // indexes[i] == q passes the above check but evaluates to f(0) == secret
    share := evaluatePolynomial(ec, threshold, poly, indexes[i])
}
```

**Attack.** An attacker sets their party ID to $q$ (the secp256k1 group order). This passes the `!= 0` integer check, but polynomial evaluation operates modulo $q$, so `evaluatePolynomial(q) ≡ evaluatePolynomial(0) = f(0)` — the secret itself. The attacker receives the complete shared key without needing reconstruction.

**Remediation.** Reduce the index modulo $q$ before comparing, and also check for duplicate indices:

```go
func validateIndex(idx, q *big.Int) error {
    reduced := new(big.Int).Mod(idx, q)
    if reduced.Sign() == 0 {
        return errors.New("party index is 0 mod q — invalid")
    }
    return nil
}
```

### Example 3: Feldman Commitment Vector Wrong Length — FROST DKG

When receiving Feldman VSS commitment vectors during a DKG round, each vector must have length exactly equal to the threshold $t$. A longer vector corresponds to a higher-degree polynomial, silently raising the threshold and potentially rendering the shared key permanently inaccessible.

([source](https://github.com/ZcashFoundation/frost/blob/a1350ea18206a812975740207f90fb121883a5b3/frost-core/src/keys/dkg.rs#L395-L446))

```rust
// frost-core/src/keys/dkg.rs — ZCash Foundation FROST (pre-fix)
pub fn part2<C: Ciphersuite>(
    secret_package: round1::SecretPackage<C>,
    round1_packages: &BTreeMap<Identifier<C>, round1::Package<C>>,
) -> Result<(round2::SecretPackage<C>, Vec<round2::Package<C>>)> {
    // Checks number of packages but NOT the length of each commitment vector
    if round1_packages.len() != (secret_package.max_signers - 1) as usize {
        return Err(Error::IncorrectNumberOfPackages);
    }
    for (sender_identifier, round1_package) in round1_packages {
        // processes commitments without validating len == min_signers
        verify_proof_of_knowledge(sender_identifier, round1_package.commitment(), ...)?;
    }
}
```

**Attack.** A malicious party sends a commitment vector of length $t + k$ ($k > 0$). Honest parties accept it, believing they are running a threshold-$t$ protocol. From this point, reconstruction requires $t + k$ shares; since honest parties hold only $t$-degree shares, the key is irrecoverable. The Trail of Bits report calls this a "key sabotage" attack.

**Remediation.** After checking the number of packages, verify each package's commitment vector length:

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

### Commit Timeline

| Date | Repository | Artifact | Description |
|------|-----------|----------|-------------|
| ~2018 | [bnb-chain/tss-lib](https://github.com/bnb-chain/tss-lib) | Initial release | Party index checked against literal 0, not $0 \bmod q$; duplicate indices not validated |
| Dec 2021 | Trail of Bits | [Shamir's Secret Sharing disclosure](https://blog.trailofbits.com/2021/12/21/disclosing-shamirs-secret-sharing-vulnerabilities-and-announcing-zkdocs/) | Index $= q$ attack across tss-lib, ZenGo-X/curv, and five downstream forks |
| Feb 2024 | Trail of Bits | [Breaking the shared key](https://blog.trailofbits.com/2024/02/20/breaking-the-shared-key-in-threshold-signature-schemes/) | Feldman commitment vector length attack; 10 implementations affected, only Chainflip had the check |
| Feb 2024 | [ZcashFoundation/frost](https://github.com/ZcashFoundation/frost) | [PR #597](https://github.com/ZcashFoundation/frost/pull/597) | Fix: per-package commitment vector length check |

### Real-World Impact

**Shamir index-0 attack (December 2021).** Trail of Bits disclosed that five downstream forks of tss-lib — Keep Network, THORChain, Swingby, Clover Network — all inherited the party-index-$q$ vulnerability. The same integer-vs-modular comparison error appeared independently in ZenGo-X/curv (Rust). While no exploitation was confirmed, any deployment between initial release and the patch window was vulnerable to a single malicious party receiving the complete shared secret.

**Feldman threshold sabotage (February 2024).** Trail of Bits found the commitment-vector-length vulnerability in 10 implementations including FROST, GG18, and GG20 reference code. An adversary who raises the threshold can deny key reconstruction indefinitely, destroying funds without any on-chain trace.
