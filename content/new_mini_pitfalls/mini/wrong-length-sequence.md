---
title: "Received sequence has the wrong length"
class: "Input Validation"
source: "improper-verification.md"
---

### Received sequence has the wrong length

**What can go wrong.** Protocols that transmit a fixed-length vector such as a Feldman VSS
commitment vector of length $t$, a list of $n-1$ peer signatures or a vector of DLN proof
iterations, must verify that the incoming length equals the expected length before
processing. Accepting a vector with unexpected length is functionally running a strictly
different protocol instance from the one the verifier thought it was in.

**Security implication.** A malicious party sends a vector of length $t + k$ when the
protocol expects length $t$. Honest verifiers iterate over all $t + k$ elements without
noticing the mismatch. In Feldman VSS this raises the reconstruction threshold from $t$ to
$t + k$ silently, rendering the shared key irrecoverable from the $t$ honest shares alone.
The sabotage is permanent: there is no on-chain trace of a raised threshold, and no retry
path without restarting the entire key-generation ceremony. A shorter-than-expected vector
breaks verification in the opposite direction. Code that indexes a fixed offset may panic
before any length check runs; code that iterates silently operates on a lower-degree
polynomial than the protocol intended.

**How to avoid.** Compare the received vector length against the protocol-specified length
before any iteration or verification step. Treat a length mismatch as a protocol abort;
do not truncate, pad, or iterate defensively.

**Example: WSTS/sBTC FROST DKG empty polynomial commitment (Issues [#1966](https://github.com/stacks-sbtc/sbtc/issues/1966) & [#212](https://github.com/xoloki/wsts/issues/212))** <!--Actually a good example for received sequence has the wrong length-->
In `xoloki/wsts`, the FROST/WSTS implementation used by Stacks sBTC, the function `PolyCommitment::verify`
indexed `self.poly[0]` without checking the vector was non-empty
([source](https://github.com/xoloki/wsts/blob/8f2a96e26c9a/src/common.rs#L35-L40)):

```rust
// src/common.rs — xoloki/wsts (vulnerable, before PR #224)
impl PolyCommitment {
    /// Verify the wrapped schnorr ID
    pub fn verify(&self, ctx: &[u8]) -> bool {
        self.id.verify(&self.poly[0], ctx)   // panics if poly is empty
    }
}
```

The function `verify` is then called by `check_public_shares`
([source](https://github.com/xoloki/wsts/blob/8f2a96e26c9a/src/common.rs#L318-L321)):

```rust
// src/common.rs — xoloki/wsts (vulnerable, before PR #224)
/// Check that the PolyCommitment is properly signed and has the correct degree polynomial
pub fn check_public_shares(poly_comm: &PolyCommitment, threshold: usize, ctx: &[u8]) -> bool {
    poly_comm.verify(ctx) && poly_comm.poly.len() == threshold
    // verify(ctx) is evaluated first; an empty poly panics before the length check runs
}
```

Deserialisation accepted an empty `poly`; calling `check_public_shares` then panicked
inside `verify` before the `poly.len() == threshold` clause was reached, crashing any
node that tried to validate the malicious commitment. The first fix ([PR #224](https://github.com/xoloki/wsts/pull/224)) both adds a
`!self.poly.is_empty()` guard inside `verify` and swaps the conjunction order in
`check_public_shares` to evaluate the length check first. A more thorough fix proposed in [PR #1968](https://github.com/stacks-sbtc/sbtc/pull/1968) introduces a
`PublicPolynomial` newtype that disallows empty vectors at construction time.

**Example: WSTS threshold-raise via oversized polynomial ([Issue #87](https://github.com/Trust-Machines/wsts/issues/87) & [PR #88](https://github.com/Trust-Machines/wsts/pull/88)).**
PR #224 above hardened a single call site against empty polynomials. The original
Trail of Bits length-check fix in `xoloki/wsts` was [PR #88](https://github.com/Trust-Machines/wsts/pull/88)
("Check length of polynomials", merged Oct 1, 2024), seven months after the
disclosure. Before that PR, the per-signer DKG verification in `src/v1.rs` only
checked the Schnorr ID, not the commitment-vector length
([source](https://github.com/Trust-Machines/wsts/blob/v9.1.0/src/v1.rs)):

```rust
// src/v1.rs — Trust-Machines/wsts (vulnerable, before PR #88)
if !comm.verify() {
    bad_ids.push(*i);
}
self.group_key += comm.poly[0];
```

A malicious signer could append commitments to its `poly` to silently raise the
reconstruction threshold — or pop one to lower it. PR #88 added the explicit
equality check at every DKG verification site:

```rust
// src/v1.rs — Trust-Machines/wsts (fixed, PR #88)
if comm.poly.len() != threshold || !comm.verify() {
    bad_ids.push(*i);
} else {
    self.group_key += comm.poly[0];
}
```

The accompanying test `bad_poly_length_dkg` mutates one signer's `poly` with
`push(...)` and another with `pop()`, exercising both length-mismatch directions.

**Example: ZenGo-X `multi-party-ecdsa` (still unfixed).** The GG20 keygen
verification function `phase2_verify_vss_construct_keypair_phase3_pok_dlog` asserts
the *number* of received VSS schemes but never the *length of each commitment
vector*
([source](https://github.com/ZenGo-X/multi-party-ecdsa/blob/7d8bd416/src/protocols/multi_party_ecdsa/gg_2020/party_i.rs#L322-L348)):

```rust
// gg_2020/party_i.rs — ZenGo-X (still vulnerable, no fix)
assert_eq!(vss_scheme_vec.len(), usize::from(params.share_count));

let correct_ss_verify = (0..y_vec.len())
    .map(|i| {
        let res = vss_scheme_vec[i]
            .validate_share(&secret_shares_vec[i], index.try_into().unwrap())
            .is_ok()
            && vss_scheme_vec[i].commitments[0] == y_vec[i];
        // ↑ no check that vss_scheme_vec[i].commitments.len() == threshold + 1
        // ...
    })
```

The repository was named in the [Trail of Bits Feb 2024 disclosure](https://blog.trailofbits.com/2024/02/20/breaking-the-shared-key-in-threshold-signature-schemes/);
the last commit (`7d8bd416`, Aug 2023) predates the disclosure and no patch has
been merged since. The codebase was widely forked by wallet implementations before
being effectively archived.

**Example: LatticeX-Foundation `opentss` (still unfixed).** The DMZ21 keygen
phase-three handler validates each share but does not enforce a length on the
incoming `vss_scheme.commitments` vector
([source](https://github.com/LatticeX-Foundation/opentss/blob/bf15ba9465bd6f27d25fe227bad7a0c9fb21281c/multi_party_ecdsa/src/protocols/multi_party/dmz21/keygen.rs#L254-L262)):

```rust
// dmz21/keygen.rs — LatticeX-Foundation/opentss (still vulnerable)
if !(msg
    .vss_scheme
    .validate_share(&msg.secret_share, self.party_index.clone())
    .is_ok()
    && msg.vss_scheme.commitments[0] == *q)
{
    return Err(anyhow!("Verify vss failed in keygen phase three"));
}
```

Trail of Bits classified `opentss` as "no response" in the Feb 2024 disclosure;
the only commit since (`bf15ba94`, Sep 2024) was an email update with no security
fix.
<!--
<div class="pitfall-flags"><span class="flag flag-shared">Shared example with <a href="#commitment-vector-length-not-checked-threshold-raise-sabotage">Commitment vector length not checked</a></span></div>

**What can go wrong.** Protocols that transmit a fixed-length vector, a Feldman VSS
commitment vector of length $t$, a list of $n-1$ peer signatures or a vector of DLN proof
iterations, must verify that the incoming length equals the expected length before
processing. Accepting a longer-than-expected vector is functionally running a strictly
different protocol instance from the one the verifier thought it was in.

**Security implication.** A malicious party sends a vector of length $t + k$ when the
protocol expects length $t$. Honest verifiers iterate over all $t + k$ elements without
noticing the mismatch. In Feldman VSS this raises the reconstruction threshold from $t$ to
$t + k$ silently, rendering the shared key irrecoverable from the $t$ honest shares alone.
The sabotage is permanent: there is no on-chain trace of a raised threshold, and no retry
path without restarting the entire key-generation ceremony.


**How to avoid.** Compare the received vector length against the protocol-specified length
before any iteration or verification step. Treat a length mismatch as a protocol abort;
do not truncate, pad, or iterate defensively.

**Example: FROST DKG commitment vector length.** The `part2` function in ZCash Foundation's
FROST implementation checked the number of round-1 packages received but not the length of
each package's commitment vector
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
    for (_, round1_package) in round1_packages {
        // processes commitments without validating len == min_signers
        verify_proof_of_knowledge(...)?;
    }
}
```

Ten implementations across FROST, GG18, and GG20 were affected; Chainflip was the only one
that had the check at the time of the Trail of Bits disclosure.
[PR #597](https://github.com/ZcashFoundation/frost/pull/597) added the per-package length
check. See the [Feldman Verified Secret Sharing](../feldman-vss/) pitfall for the full
writeup.

--->
