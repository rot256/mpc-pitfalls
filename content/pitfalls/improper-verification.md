---
title: "Improper Verification of Received Messages"
class: "Missing Data Validation"
order: 1
---
<!--class: "Received-Message Validation"-->
<!--In MPC protocols, parties exchange bitstrings that are supposed to represent mathematical
objects: elements of $\mathbb{Z}_q^*$, commitments to polynomial coefficients,
zero-knowledge proofs, and lists of peer contributions. In the context of secret sharing, a related concern is that the
**domain of secrets**, the values a party is logically supposed to contribute, is often much
smaller than the **domain of shares**, the algebraic ring or field over which the protocol
computes. A 1-bit boolean secret is shared over $\mathbb{F}_p$ for a large prime $p$; a
64-bit integer is shared over $\mathbb{Z}_{2^{128}}$; a Schnorr/ECDSA message hash must
lie in $\mathbb{Z}_q$. Before the receiver uses an incoming bitstring, it must verify both
that the bitstring corresponds to a *valid* object of the expected type and that its value
lies within the expected secret space. The pitfalls below are what goes wrong when that
verification is skipped or performed in the wrong domain.-->

In MPC protocols, parties exchange data encoded as bitstrings that represent mathematical
objects such as elements of $\mathbb{Z}_q^*$, commitments to polynomial coefficients,
zero-knowledge proofs, or lists of peer contributions. The
protocol guarantees correct computation on whatever inputs the parties supply; it does not
constrain those inputs. A corrupted party may submit any value, so if an application's
security depends on well-formed inputs, the implementation must enforce that separately.

In secret-sharing-based MPC, the **domain of secrets**, the admissible inputs of the
function, and the **domain of shares**, the algebraic structure over which the sharing
scheme operates, usually do not match. For example, a one-bit boolean secret may be shared over
$\mathbb{F}_p$ for a large prime $p$; a
64-bit integer is shared over $\mathbb{Z}_{2^{128}}$; a Schnorr/ECDSA message hash must
lie in $\mathbb{Z}_q$. Before using an incoming message, the receiver must
verify that the message has the expected shape, that each component decodes to a valid object of the expected algebraic type,
and that each value satisfies the constraints of the secret or input domain. The pitfalls
below arise when one of these checks is omitted, applied only to the encoding, or performed
in the wrong domain.

### Empty proof list passes vacuously

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

### Non-zero check performed in the wrong domain

<!--<div class="pitfall-flags"><span class="flag flag-shared">Shared example with <a href="#party-index-not-validated-as-non-zero-mod-q">Party index not validated as non-zero mod q</a></span></div>-->

**What can go wrong.** When a received value $x$ must be rejected if it is zero in
$\mathbb{Z}_q^*$, the check must be `x mod q != 0`, not `x != 0` in integer arithmetic. A
value $x = k \cdot q$ for any integer $k$ passes the integer comparison but is zero in the
protocol's arithmetic domain. The same mistake generalises to any modular or curve-scalar
setting where the wire representation can exceed the modulus without the type system
flagging it.

**Security implication.** A malicious party sends a value that is zero in the protocol's
arithmetic domain but non-zero in the language's integer type. The honest verifier accepts
it, and downstream operations silently collapse: polynomial evaluation at zero returns the
constant term; modular inversion of zero blows up or returns zero; Pedersen commitments
degenerate to trivial openings. In Shamir secret sharing, an attacker who submits $x = q$
as its "index" receives $f(q) \equiv f(0) = \text{secret}$.

**How to avoid.** Reduce received values modulo the protocol's arithmetic domain *before*
the zero check, e.g. `new(big.Int).Mod(x, q).Sign() == 0`. Apply the same discipline to
every $\mathbb{Z}_q^*$ membership test; integer comparisons against the literal `0` are
not sufficient.

**Example: juicebox-sdk allows index 0 on reconstruction ([Issue #6](https://github.com/juicebox-systems/juicebox-sdk/issues/6)).**
In `juicebox-systems/juicebox-sdk`'s Shamir
secret-sharing crate, share creation enforces non-zero indices structurally
(`(1..=count).map(Index)`), but `recover_secret` runs Lagrange interpolation over
whatever indices the caller supplies, with no reconstruction-time check
([source](https://github.com/juicebox-systems/juicebox-sdk/blob/main/rust/secret_sharing/src/lib.rs#L97-L117)):

```rust
// rust/secret_sharing/src/lib.rs — juicebox-systems/juicebox-sdk (vulnerable)
pub fn recover_secret<S: Secret>(shares: &[Share<S>]) -> Result<S, RecoverSecretError> {
    shares
        .iter()
        .enumerate()
        .map(|(i, share)| {
            let others = shares[..i].iter().chain(&shares[i + 1..]);
            let numerator: Scalar = others
                .clone()
                .map(|other_share| other_share.index.as_scalar())
                .product();
            let denominator: Scalar = others
                .map(|other_share| other_share.index.as_scalar() - share.index.as_scalar())
                .product();
            // No check that share.index != 0; an attacker-supplied index 0
            // makes their share's secret dominate the reconstruction.
            ...
        })
        .sum()
}
```

A malicious party submits `Share { index: Index(0), secret: x }` for any chosen `x`, so the recovered secret collapses to the attacker-chosen `x`. The bug is unfixed at the time of writing.
<!--; the underlying
type is `curve25519-dalek::scalar::Scalar`, so the integer-vs-modular distinction does
not apply here.-->
<!--**Example: tss-lib party index `== q`.** In `bnb-chain/tss-lib`, party indices for the
Feldman VSS share assignment were compared against the integer literal `0` only
([source](https://github.com/bnb-chain/tss-lib/blob/73560daec7f83d7355107ea9b5e59d16de8765be/crypto/vss/feldman_vss.go#L64-L70)):

```go
// crypto/vss/feldman_vss.go — bnb-chain/tss-lib (vulnerable)
for i := 0; i < num; i++ {
    if indexes[i].Cmp(big.NewInt(0)) == 0 {
        return nil, nil, fmt.Errorf("party index should not be 0")
    }
    // indexes[i] == q passes the check; evaluatePolynomial(q) ≡ f(0) = secret
    share := evaluatePolynomial(ec, threshold, poly, indexes[i])
}
```

A party that sets its ID to the secp256k1 group order $q$ passes the `!= 0` check, but
polynomial evaluation runs modulo $q$, so the returned "share" is $f(0)$, the shared
secret. See the [Shamir Secret Sharing](../shamir-secret-sharing/) pitfall for the full
writeup and remediation.
-->
### Subgroup-generator check missing

<div class="pitfall-flags"><!--<span class="flag flag-tbd">TBD example</span>--><span class="flag flag-related">Closely related to <a href="#group-generator-not-validated">Group generator not validated</a></span></div>

**What can go wrong.** A received value that is supposed to generate a non-trivial subgroup
must be checked to actually do so. At minimum, it must not be the identity (1 in a
multiplicative group, the point at infinity on a curve) and must have the expected order
(typically a large prime $q$). A received "generator" that equals 1 generates only the
trivial subgroup; a generator of order 2 or 4 on an RSA-style modulus leaks one or two bits
of any secret exponent per operation. Accepting an adversary-supplied generator without an
order check is the same mistake as accepting a zero field element, applied one level up the
algebraic hierarchy.

**Security implication.** A malicious party supplies a trivial or small-order generator as
its contribution to a shared protocol parameter, e.g. a Pedersen base, a DLN proof base or a
Paillier auxiliary generator. The honest verifier then uses it in exponentiations with its
own secret exponent, and each exponentiation leaks the low bits of that exponent. Across a
handful of rounds the attacker recovers the secret exponent completely, that is, a Pohlig–Hellman
decomposition in disguise.

**How to avoid.** Before using an adversary-supplied group element in any exponentiation,
verify it has the expected subgroup order. For example, on RSA-style moduli, check
$x^q \equiv 1 \pmod{N}$ and $x \notin \{1, N-1\}$; on non-prime-order curves, multiply by the
cofactor and reject the identity; on prime-order curves, reject the identity (point at
infinity).

<!--**Example.** *TBD on this page.* The concrete instances on this site live in the
[Discrete-Log Groups](../discrete-log-groups/) pitfall (generator validation; $g = \pm 1
\bmod p$ leaks the exponent LSB) and the [RSA / Paillier Moduli](../rsa-moduli/) pitfall
(missing DLN proofs for $h_1$, $h_2$ on Pedersen bases, CVE-2020-12118). Either is a worked
instance of this general failure.-->

**Example: Symbiotic Relay BLS key registration accepts non-subgroup points ([Sherlock #98](https://github.com/sherlock-audit/2025-06-symbiotic-relay-judging/issues/98)).**
In Symbiotic Relay's middleware SDK, `KeyBlsBn254.wrap()` validates an incoming BN254
G1 point as a validator BLS public key but only checks coordinate bounds and curve
membership ($y^2 \equiv x^3 + 3 \pmod p$); it does *not* check subgroup membership
([source](https://github.com/sherlock-audit/2025-06-symbiotic-relay/blob/main/middleware-sdk/src/contracts/libraries/keys/KeyBlsBn254.sol#L17-L34)):

```solidity
// middleware-sdk/src/contracts/libraries/keys/KeyBlsBn254.sol — Symbiotic Relay (vulnerable)
function wrap(
    BN254.G1Point memory keyRaw
) internal view returns (KEY_BLS_BN254 memory key) {
    if (keyRaw.X == 0 && keyRaw.Y == 0) {
        return zeroKey();
    }
    if (keyRaw.X >= BN254.FP_MODULUS || keyRaw.Y >= BN254.FP_MODULUS) {
        revert KeyBlsBn254_InvalidKey();
    }
    (uint256 beta, uint256 derivedY) = BN254.findYFromX(keyRaw.X);
    if (mulmod(derivedY, derivedY, BN254.FP_MODULUS) != beta) {
        revert KeyBlsBn254_InvalidKey();
    }
    if (keyRaw.Y != derivedY && keyRaw.Y != BN254.FP_MODULUS - derivedY) {
        revert KeyBlsBn254_InvalidKey();
    }
    // MISSING: subgroup check — cofactor·keyRaw should equal point at infinity
    key = KEY_BLS_BN254(keyRaw);
}
```

BN254 has cofactor $h > 1$, so the curve contains small-order points outside the
prime-order subgroup. An attacker registers such a point as their validator key; every
subsequent BLS aggregation that includes it operates outside the subgroup the security
proof assumes, and the pairing equation becomes satisfiable for crafted signatures
without knowledge of the corresponding private key. The audit's recommended fix is the
standard `cofactor·P == 0` check before storing the key.

<!--**Example: Symbiotic Relay BLS verification skips subgroup checks on calldata-supplied points ([Sherlock #76](https://github.com/sherlock-audit/2025-06-symbiotic-relay-judging/issues/76)).**
The same omission appears on the verification side. `SigBlsBn254.verify()` decodes
attacker-controlled `signatureG1` (G1) and `keyG2` (G2) from calldata and feeds them
directly into `BN254.safePairing(...)` with no subgroup-membership check on either point
([source](https://github.com/sherlock-audit/2025-06-symbiotic-relay/blob/main/middleware-sdk/src/contracts/libraries/sigs/SigBlsBn254.sol#L13-L42)):

```solidity
// middleware-sdk/src/contracts/libraries/sigs/SigBlsBn254.sol — Symbiotic Relay (vulnerable)
function verify(
    bytes memory keyBytes,
    bytes memory message,
    bytes memory signature,
    bytes memory extraData
) internal view returns (bool) {
    // ...
    BN254.G2Point memory keyG2 = abi.decode(extraData, (BN254.G2Point));
    BN254.G1Point memory signatureG1 = abi.decode(signature, (BN254.G1Point));
    // MISSING: subgroup checks on signatureG1 (G1) and keyG2 (G2) before pairing
    (bool success, bool result) = BN254.safePairing(
        signatureG1.plus(keyG1.scalar_mul(alpha)),
        BN254.negGeneratorG2(),
        messageG1.plus(BN254.generatorG1().scalar_mul(alpha)),
        keyG2,
        PAIRING_CHECK_GAS_LIMIT
    );
    return success && result;
}
```

The pairing equation is satisfiable by points that lie on the curve but outside the
prime-order subgroup, so an attacker can craft a `(signatureG1, keyG2)` pair that passes
`verify()` without knowing the corresponding private key — a complete signature-forgery
primitive against the consensus-layer authentication. The audit's recommended fix is
explicit `BN254.inG1Subgroup(signatureG1)` and `BN254.inG2Subgroup(keyG2)` calls before
the pairing, or renaming `verify` to `unsafeVerify` and pushing the obligation to
callers. Both Sherlock #98 and #76 were filed in the June 2025 contest and are open at
the time of writing.-->

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

<!--
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
-->
