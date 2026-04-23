---
title: "Improper Verification of Received Messages"
class: "Received-Message Validation"
order: 1
---

In MPC protocols, parties exchange bitstrings that are supposed to represent mathematical
objects: elements of $\mathbb{Z}_q^*$, commitments to polynomial coefficients,
zero-knowledge proofs, and lists of peer contributions. A related concern is that the
**secret space** — the values a party is logically supposed to contribute — is often much
smaller than the **share space**, the algebraic ring or field over which the protocol
computes. A 1-bit boolean secret is shared over $\mathbb{F}_p$ for a large prime $p$; a
64-bit integer is shared over $\mathbb{Z}_{2^{128}}$; a Schnorr / ECDSA message hash must
lie in $\mathbb{Z}_q$. Before the receiver uses an incoming bitstring, it must verify both
that the bitstring corresponds to a *valid* object of the expected type and that its value
lies within the expected secret space. The pitfalls below are what goes wrong when that
verification is skipped or performed in the wrong domain.

### Empty proof list passes vacuously

<div class="pitfall-flags"><span class="flag flag-tbd">TBD example</span></div>

**What can go wrong.** A protocol round that expects a list of zero-knowledge proofs (one
per party, one per commitment coefficient, one per witness) must reject an empty list
explicitly. In most languages, a `for-each` loop over an empty collection executes zero
iterations and returns no error, which is syntactically indistinguishable from a loop over
a list in which every proof passed. A caller that only checks whether the verification
function returned an error treats an empty list as "all proofs valid."

**Security implication.** A malicious party sends an empty proof list when the protocol
expects $n-1$ proofs. The verifier iterates zero times, returns success, and the protocol
proceeds as if every proof had been correctly verified. In a DKG this lets the adversary
contribute arbitrarily biased public-share values without demonstrating knowledge of the
matching secrets; in a signing round it lets the adversary skip any proof-of-correctness
obligation and substitute crafted partial values.

**How to avoid.** Check `len(proofs) == expected` before iterating; never infer "all
proofs valid" from "no error was returned."

**Example.** *TBD.* Trail of Bits has flagged this pattern across multiple MPC audits but
no specific public CVE is attached to this mini-pitfall yet.

### Non-zero check performed in the wrong domain

<div class="pitfall-flags"><span class="flag flag-shared">Shared example with <a href="#party-index-not-validated-as-non-zero-mod-q">Party index not validated as non-zero mod q</a></span></div>

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
the zero check — e.g. `new(big.Int).Mod(x, q).Sign() == 0`. Apply the same discipline to
every $\mathbb{Z}_q^*$ membership test; integer comparisons against the literal `0` are
not sufficient.

**Example: tss-lib party index `== q`.** In `bnb-chain/tss-lib`, party indices for the
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
polynomial evaluation runs modulo $q$, so the returned "share" is $f(0)$ — the shared
secret. See the [Shamir Secret Sharing](../shamir-secret-sharing/) pitfall for the full
writeup and remediation.

### Subgroup-generator check missing

<div class="pitfall-flags"><span class="flag flag-tbd">TBD example</span><span class="flag flag-related">Closely related to <a href="#group-generator-not-validated">Group generator not validated</a></span></div>

**What can go wrong.** A received value that is supposed to generate a non-trivial subgroup
must be checked to actually do so. At minimum, it must not be the identity (1 in a
multiplicative group, the point at infinity on a curve) and must have the expected order
(typically a large prime $q$). A received "generator" that equals 1 generates only the
trivial subgroup; a generator of order 2 or 4 on an RSA-style modulus leaks one or two bits
of any secret exponent per operation. Accepting an adversary-supplied generator without an
order check is the same mistake as accepting a zero field element, applied one level up the
algebraic hierarchy.

**Security implication.** A malicious party supplies a trivial or small-order generator as
its contribution to a shared protocol parameter — a Pedersen base, a DLN proof base, a
Paillier auxiliary generator. The honest verifier then uses it in exponentiations with its
own secret exponent, and each exponentiation leaks the low bits of that exponent. Across a
handful of rounds the attacker recovers the secret exponent completely — a Pohlig–Hellman
decomposition in disguise.

**How to avoid.** Before using an adversary-supplied group element in any exponentiation,
verify it has the expected subgroup order: on RSA-style moduli, check
$x^q \equiv 1 \pmod{N}$ and $x \ne 1, N-1$; on non-prime-order curves, multiply by the
cofactor and reject the identity; on prime-order curves, reject the identity (point at
infinity).

**Example.** *TBD on this page.* The concrete instances on this site live in the
[Discrete-Log Groups](../discrete-log-groups/) pitfall (generator validation; $g = \pm 1
\bmod p$ leaks the exponent LSB) and the [RSA / Paillier Moduli](../rsa-moduli/) pitfall
(missing DLN proofs for $h_1$, $h_2$ on Pedersen bases, CVE-2020-12118). Either is a worked
instance of this general failure.

### Received sequence has the wrong length

<div class="pitfall-flags"><span class="flag flag-shared">Shared example with <a href="#commitment-vector-length-not-checked-threshold-raise-sabotage">Commitment vector length not checked</a></span></div>

**What can go wrong.** Protocols that transmit a fixed-length vector — a Feldman VSS
commitment vector of length $t$, a list of $n-1$ peer signatures, a vector of DLN proof
iterations — must verify that the incoming length equals the expected length before
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
