---
title: "Empty Proof List Passes Vacuously"
class: "Others"
source: "improper-verification.md"
---

### Empty Proof List Passes Vacuously

<!--<div class="pitfall-flags"><span class="flag flag-tbd">TBD example</span></div>-->

**What can go wrong.** A protocol round that expects a list of zero-knowledge proofs (one
per party, one per commitment coefficient, one per witness) must reject an empty list
explicitly. In most languages, a `for-each` loop over an empty collection executes zero
iterations and returns no error, which is syntactically indistinguishable from a loop over
a list in which every proof passed. A caller that only checks whether the verification
function returned an error treats an empty list as "all proofs valid."

**Security implication.** A malicious party sends an empty proof list when the protocol
expects $n-1$ proofs. The verifier iterates zero times, returns success, and the protocol
proceeds as if every proof had been correctly verified. In a DKG (Distributed Key Generation) this lets the adversary
contribute arbitrarily biased public-share values without demonstrating knowledge of the
matching secrets; in a signing round it lets the adversary skip any proof-of-correctness
obligation and substitute crafted partial values.

**How to avoid.** Check `len(proofs) == expected` before iterating; never infer "all
proofs valid" from "no error was returned."

<!--**Example.** *TBD.* Trail of Bits has flagged this pattern across multiple MPC audits but
no specific public CVE is attached to this mini-pitfall yet.
 -->

**Example: Aptos validator-verifier zero-quorum bypass ([Issue #61](https://github.com/Lchangliang/gravity-aptos/issues/61))** In the `Lchangliang/gravity-aptos` fork of `aptos-core`, `ValidatorVerifier::verify_multi_signatures`
short-circuits to `Ok(())` whenever the verifier holds an empty validator set, because
`quorum_voting_power == 0` makes the check `aggregated < target` evaluate as
`0 < 0 == false`
([source](https://github.com/Lchangliang/gravity-aptos/blob/master/types/src/validator_verifier.rs#L344-L385)):

```rust
// types/src/validator_verifier.rs#L344-L385 — Lchangliang/gravity-aptos (vulnerable)
pub fn verify_multi_signatures<T: CryptoHash + Serialize>(
    &self,
    message: &T,
    multi_signature: &AggregateSignature,
) -> std::result::Result<(), VerifyError> {
    // Verify the number of signature is not greater than expected.
    Self::check_num_of_voters(self.len() as u16, multi_signature.get_signers_bitvec())?;
    let mut pub_keys = vec![];
    let mut authors = vec![];
    for index in multi_signature.get_signers_bitvec().iter_ones() {
        // empty signers bitvec: loop body never executes
        let validator = self
            .validator_infos
            .get(index)
            .ok_or(VerifyError::UnknownAuthor)?;
        authors.push(validator.address);
        pub_keys.push(validator.public_key());
    }
    // Verify the quorum voting power of the authors
    self.check_voting_power(authors.iter(), true)?;     // 0 < 0 == false → passes
    #[cfg(any(test, feature = "fuzzing"))]
    {
        if self.quorum_voting_power == 0 {
            // This should happen only in case of tests.
            // TODO(skedia): Clean up the test behaviors to not rely on empty signature
            // verification
            return Ok(());                              // returns success before BLS pairing
        }
    }
    // Verify empty multi signature
    let multi_sig = multi_signature
        .sig()
        .as_ref()
        .ok_or(VerifyError::EmptySignature)?;
    // Verify the optimistically aggregated signature.
    let aggregated_key =
        PublicKey::aggregate(pub_keys).map_err(|_| VerifyError::FailedToAggregatePubKey)?;

    multi_sig
        .verify(message, &aggregated_key)
        .map_err(|_| VerifyError::InvalidMultiSignature)?;
    Ok(())
}
```

`EpochState::empty()` constructs exactly such a zero-validator verifier. Any code path
that lets a malicious or deserialised `EpochState` reach `verify_multi_signatures`
(e.g. a `next_epoch_state` injected through an `EpochChangeProof`) yields a verifier
that accepts every `LedgerInfo` regardless of the BLS multisignature attached to it:
the iterator over signers runs zero times, the `aggregated < target` quorum check
passes vacuously, and the `fuzzing` cfg-block returns `Ok(())` before the BLS pairing
is computed. While no
fix has been merged at the time of writing, the issue itself sketches three remediation
steps.


<!-- Not relevant
--- 


**Candidate 3 — Taurus `multi-party-sig` (CGGMP21) ZK proofs: nil-receiver panic across seven proofs.**
In `taurushq-io/multi-party-sig`, the `Verify` methods on the CGGMP21 ZK proofs (`affg`,
`affp`, `elog`, `enc`, `encelg`, `log`, `logstar`) were value receivers, so dispatching
`Verify` on a `nil` proof — which is what wire-level deserialisation produces when the
proof field is omitted — segfaulted instead of returning `false`
([pre-fix source](https://github.com/taurushq-io/multi-party-sig/blob/v0.6.0-alpha-2021-09-21/pkg/zk/log/log.go#L77-L82)):

```go
// pkg/zk/log/log.go — taurushq-io/multi-party-sig (vulnerable, before PR #100)
func (p Proof) Verify(hash *hash.Hash, public Public) bool {
    if !p.IsValid() {        // nil-receiver value cast panics before this line
        return false
    }
    // ...
}
```

[PR #100](https://github.com/taurushq-io/multi-party-sig/pull/100) flipped all seven
receivers to pointer receivers (`func (p *Proof) Verify`), so `p == nil` reaches
`p.IsValid()` and returns `false`. *Adjacent root cause — a missing absent-proof guard —
but the symptom is a panic, and the fix doesn't add a positive list-length check.*

---

**Candidate 4 — pluto/ronkathon BLS aggregation: empty-list panic in educational code.**
The `BlsSignature::aggregate` function indexes `signatures[0]` with no non-empty check
([source per issue body](https://github.com/pluto/ronkathon/issues/251)):

```rust
// src/signatures/bls/mod.rs — pluto/ronkathon (vulnerable)
pub fn aggregate(signatures: &[BlsSignature<C>]) -> Result<BlsSignature<C>, BlsError> {
    let mut aggregated = signatures[0].clone();   // panics on empty input
    for sig in &signatures[1..] {
        aggregated = aggregated + sig;
    }
    Ok(aggregated)
}
```

Reported as [pluto/ronkathon#251](https://github.com/pluto/ronkathon/issues/251).
*Educational repo, not production deployed; included only as a clean illustration of the
pattern.*-->

<!-- DRAFT END -->
