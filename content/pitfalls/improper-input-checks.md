---
title: "Improper Input Checks"
class: "Received-Message Validation"
order: 2
---

### Input not reduced to the arithmetic domain

**What can go wrong.** When a protocol's arithmetic domain is $\mathbb{Z}_q$ (or
$\mathbb{Z}_{2^k}$, or any modular ring), an incoming bitstring is untyped — it can encode
a raw integer $x$ outside the modulus. If the protocol accepts $x$ verbatim without
reducing modulo $q$ or range-checking against $q$, two byte-distinct wire values $x$ and
$x + q$ represent the same algebraic element. Downstream consumers that see only the raw
bytes then treat them as different inputs. Protocols claiming malicious security carry a
specific obligation here: every party's input must be checked or proven well-formed
*before* it enters the authenticated state.

**Security implication.** A malicious orchestrator submits $m' = m + q$ (or any
$m' \equiv m \pmod{q}$ with $m' \ne m$). All parties compute the same signature, MAC, or
commitment for $m'$ as for $m$, but an external verifier treating the raw bytes as the
signed message accepts both as valid signatures — breaking single-signature-per-message
unforgeability. More broadly, unvalidated out-of-domain inputs produce correctness
violations (silent modular wrap-around that parties accept as correct output) or privacy
violations (biased reconstructions that leak one bit of an honest party's input per
session).

**How to avoid.** Reject inputs at the protocol boundary: before accepting any bitstring
as a domain element, verify its integer value lies in $[0, q)$ (or the ring-appropriate
range). A single `value.Cmp(modulus) < 0` check at every entry point is usually
sufficient.

**Example: tss-lib ECDSA signing accepts messages $\ge q$ (Issue #55).** In
`bnb-chain/tss-lib` before October 2019, the `Sign()` entry-point accepted an arbitrary
`*big.Int` without checking it lay in $[0, q)$
([source](https://github.com/bnb-chain/tss-lib/issues/55)):

```go
// FILE: ecdsa/signing/local_party.go — bnb-chain/tss-lib (vulnerable, pre-Oct 2019)
func NewLocalParty(
    msg *big.Int,   // ← accepted verbatim; no check that msg < curveN
    params *tss.Parameters,
    key keygen.LocalPartySaveData,
    out chan<- tss.Message,
    end chan<- common.SignatureData,
) tss.Party {
    ...
    p.temp.m = msg  // stored and used in round 1 without reduction
    ...
}
```

A malicious orchestrator submits $m' = m + q$. All parties compute a signature for $m'$
but the bytes of $m'$ differ from $m$; an external verifier treating the raw bytes as
the signed message accepts both as valid signatures. The fix
([Issue #55](https://github.com/bnb-chain/tss-lib/issues/55), landed October 17, 2019)
added an explicit range check at the entry-point:

```go
curveN := params.EC().Params().N
if msg.Cmp(curveN) != -1 {
    return nil, fmt.Errorf("signing message is not in Z_q")
}
```

<!--
### Alternative worked examples preserved from earlier DRAFT

Four more examples (Final Signature Not Verified, SPDZ2k Wrong MAC Modulus, Bit-Input
Shares Not Validated, HighGear Security Parameter Degradation) covered distinct concerns
that are adjacent to this pitfall but are not themselves "input not reduced to the
arithmetic domain." They are preserved here in case they deserve their own mini-pitfall
page later.

### Example: Final Signature Not Verified Against the Group Public Key — tss-lib (Issue #55)

After all threshold parties contribute their partial signatures and the coordinator reconstructs $(r, s)$, the assembled signature must be verified against the group public key before being returned to the caller. Without this check, a malicious participant who submits a corrupted partial response causes the protocol to output a signature that fails external verification — an attack that would not be detected until a downstream consumer (e.g., a blockchain node) rejects the transaction, at which point the signing session's nonce $k$ has been consumed and the attack may have revealed information about partial secrets.

In `bnb-chain/tss-lib` before October 2019, `finalize.go` reconstructed $(r, s)$ and returned immediately without verifying ([source](https://github.com/bnb-chain/tss-lib/issues/55)):

```go
// FILE: ecdsa/signing/finalize.go — bnb-chain/tss-lib (vulnerable)

// r and s are assembled from threshold shares
// No call to ecdsa.Verify() — the signature is returned as-is
return &common.SignatureData{
    R: r.Bytes(),
    S: s.Bytes(),
}, nil
```

**Attack.** A malicious participant provides a valid-looking partial signature $s_i'$ that is crafted so the reconstruction of $s = \sum s_i$ fails ECDSA verification. The protocol does not detect this and returns the invalid $(r, s)$ to the caller. The caller then attempts to broadcast the transaction — which will be rejected — while the malicious party has consumed the honest parties' nonce commitments, potentially gaining information toward key extraction depending on the protocol variant.

**Remediation.** Commit [`9f398c9`](https://github.com/bnb-chain/tss-lib/commit/9f398c92def051a66cb23d4f8087cf5d6422f7d4) (October 17, 2019) added a standard library ECDSA verification call in the finalization step ([source](https://github.com/bnb-chain/tss-lib/blob/9f398c92def051a66cb23d4f8087cf5d6422f7d4/ecdsa/signing/finalize.go)):

```go
// FILE: ecdsa/signing/finalize.go — bnb-chain/tss-lib (fixed)

import gecdsa "crypto/ecdsa"

pk := &gecdsa.PublicKey{
    Curve: params.EC(),
    X:     key.ECDSAPub.X(),
    Y:     key.ECDSAPub.Y(),
}
if ok := gecdsa.Verify(pk, msg.Bytes(), new(big.Int).SetBytes(R), new(big.Int).SetBytes(S)); !ok {
    return nil, fmt.Errorf("signature verification failed")
}
```

### Example: Wrong MAC Check on SPDZ2k Input Tuples (MP-SPDZ v0.2.2)

SPDZ2k is a variant of SPDZ that operates over the ring $\mathbb{Z}_{2^k}$ rather than a prime field. Authentication is achieved by holding MAC shares under a global key $\alpha$. However, because $\mathbb{Z}_{2^k}$ has different algebraic structure from $\mathbb{F}_p$, the MAC check equation must be adapted: the statistical security parameter $s$ ensures that the MAC acts like an information-theoretic authenticator modulo $2^{k+s}$, not just modulo $2^k$.

In MP-SPDZ before v0.2.2, the input-tuple generation for SPDZ2k computed the MAC check against the wrong modulus. Concretely, when a party $i$ wishes to input value $x$, it broadcasts a masked version $x + r$ (where $r$ is preprocessed randomness), and all parties verify the MAC on the reconstructed $x$. The verification equation was:

```
// Vulnerable: MAC check performed modulo 2^k instead of 2^(k+s)
// This means the adversary only needs to find a collision modulo 2^k,
// rather than the statistically secure 2^(k+s).
check = (alpha * x) mod 2^k    // ← should be mod 2^(k+s)
```

**Attack.** With the check performed modulo $2^k$ instead of $2^{k+s}$, the effective statistical security of the input authentication is reduced from $s$ bits to $0$ bits — the MAC check becomes a purely algebraic equation that a malicious party can satisfy for *any* input value by constructing a forgery modulo $2^k$. In practice, an adversary inputs $x' = x + 2^k \cdot \delta$ for any chosen $\delta$, which is indistinguishable from $x$ modulo $2^k$ and passes the incorrect check while shifting the computation result by a known offset $\delta$.

**Remediation.** Version 0.2.2 (commit [`253ece7`](https://github.com/data61/MP-SPDZ/commit/253ece7844bbd410234d3d3c8b9b2da22fa368f2), January 21, 2020) corrected the MAC verification to operate over the full $2^{k+s}$ ring ([source](https://github.com/data61/MP-SPDZ/blob/253ece7844bbd410234d3d3c8b9b2da22fa368f2/Protocols/SPDZ2k.hpp)):

```cpp
// FILE: Protocols/SPDZ2k.hpp — MP-SPDZ (fixed, v0.2.2)

// MAC check now uses the statistically-secure extended ring Z_{2^{k+s}}
// rather than the computation ring Z_{2^k}
check = (alpha * x) % (1 << (k + s));  // ← correct modulus
```

### Example: Bit-Input Shares Not Validated in Malicious Random-Bit Generation (MP-SPDZ)

Many MPC protocols require jointly generating a uniform random bit $b \in \{0,1\}$. A standard approach is for each party $i$ to secret-share a locally chosen bit $b_i$, then XOR all shares: $b = b_1 \oplus \cdots \oplus b_n$. Under malicious security, each party must also *prove* that its contribution is a valid bit share. Several protocols in MP-SPDZ with supposed malicious security omitted this check: the party's input was accepted as a field element without verifying it reconstructs to $\{0, 1\}$ ([source](https://github.com/data61/MP-SPDZ/blob/master/Protocols/MascotPrep.hpp)).

```cpp
// FILE: Protocols/MascotPrep.hpp — MP-SPDZ (vulnerable, pre-fix)

// Each party contributes b_i to a joint random-bit generation.
// The protocol checks the MAC on b_i but does NOT check that b_i ∈ {0, 1}.
// A malicious party can submit b_i = 42 and the MAC check will still pass
// (since the MAC is on the value 42, not on whether it is a valid bit).
template<class T>
void MascotPrep<T>::buffer_bits() {
    ...
    // missing: assert(reconstructed_b == 0 || reconstructed_b == 1)
    bits.push_back(share);
}
```

**Attack.** Malicious party $P_m$ contributes $b_m = v$ for an arbitrary field element $v \notin \{0,1\}$. The reconstructed "random bit" is $b = v \oplus \bigoplus_{i \ne m} b_i$, which is no longer a bit. If the resulting $b$ is used to mask an honest party's input in a subsequent protocol step (e.g., as an oblivious transfer selector or a garbled circuit wire label), the biased value can shift the masked result in a way that leaks a bit of the honest party's input to $P_m$. Repeating across multiple random-bit calls allows accumulation of information about private inputs.

**Remediation.** The fix added an explicit reconstruction and range check after each party's contribution is collected, aborting the protocol if any share lies outside $\{0, 1\}$ ([source](https://github.com/data61/MP-SPDZ/blob/master/Protocols/MascotPrep.hpp)):

```cpp
// FILE: Protocols/MascotPrep.hpp — MP-SPDZ (fixed)

// After MAC check passes, verify the reconstructed value is a valid bit
auto reconstructed = reconstruct(share);
if (reconstructed != 0 && reconstructed != 1) {
    throw invalid_bit_share();
}
bits.push_back(share);
```

### Example: HighGear Input Protocol Security Parameter Degradation (MP-SPDZ v0.4.2)

HighGear is an offline-phase protocol that uses somewhat-homomorphic encryption to generate authenticated multiplication triples and input masks with active security. Input authentication in HighGear involves a statistical security parameter $\sigma$ (typically 40 or 80 bits) that bounds the probability of an adversary forging a MAC on a malformed input. In MP-SPDZ before v0.4.2, a minor arithmetic error in the parameter selection caused the effective security level to be smaller than the configured value — the ring used for the input MAC was narrower than intended, reducing $\sigma$ by several bits.

**Attack.** The degradation is not an immediate full break — the semantic security of the underlying LWE problem remains intact. However, the statistical MAC forgery probability increases from $2^{-\sigma}$ to $2^{-(\sigma - \delta)}$ for some small $\delta$ determined by the off-by-one in ring sizing. For deployments using the minimum recommended $\sigma = 40$, the effective security could drop to the low-30s, which falls below the conventionally accepted 40-bit statistical security floor. An adversary willing to run $\approx 2^{33}$ parallel signing sessions could eventually forge a valid-looking input MAC.

**Remediation.** Version 0.4.2 (commit [`bf7f8f4`](https://github.com/data61/MP-SPDZ/commit/bf7f8f4b65e4653b5353fe652005319651794834), December 24, 2024) corrected the ring-size calculation to restore the full $\sigma$ bits ([source](https://github.com/data61/MP-SPDZ/blob/bf7f8f4b65e4653b5353fe652005319651794834/Protocols/HighGear.hpp)):

```cpp
// FILE: Protocols/HighGear.hpp — MP-SPDZ (fixed, v0.4.2)

// Previously: ring size was computed as ceil(log2(p)) + sigma
// (off-by-one due to not accounting for the carry bit in the MAC check)
// Fixed: ring size = ceil(log2(p)) + sigma + 1
int ring_size = numBits(field_prime) + sec_param + 1;
```

### Commit Timeline

| Date | Repository | Artifact | Description |
|------|-----------|----------|-------------|
| Sep 23, 2019 | [bnb-chain/tss-lib](https://github.com/bnb-chain/tss-lib) | [Issue #55](https://github.com/bnb-chain/tss-lib/issues/55) | Kudelski Security audit identifies: message not in $\mathbb{Z}_q$, missing final signature verification, `PrepareForSigning()` lacks bounds checks |
| Oct 17, 2019 | [bnb-chain/tss-lib](https://github.com/bnb-chain/tss-lib) | [commit `9f398c9`](https://github.com/bnb-chain/tss-lib/commit/9f398c92def051a66cb23d4f8087cf5d6422f7d4) | Fix: add $\mathbb{Z}_q$ range check on signing message and add `ecdsa.Verify()` call in finalization |
| Apr 30, 2020 | [data61/MP-SPDZ](https://github.com/data61/MP-SPDZ) | v0.0.9 / [commit `b5d8123`](https://github.com/data61/MP-SPDZ/commit/b5d8123ae08e6921cbdfa2b5decbe7608da3414e) | Fix: information leakage when opening linear combinations of private inputs in MASCOT and SPDZ2k with more than two parties |
| Jan 21, 2020 | [data61/MP-SPDZ](https://github.com/data61/MP-SPDZ) | v0.2.2 / [commit `253ece7`](https://github.com/data61/MP-SPDZ/commit/253ece7844bbd410234d3d3c8b9b2da22fa368f2) | Fix: wrong MAC check in SPDZ2k input tuple generation; MAC was verified modulo $2^k$ instead of $2^{k+s}$ |
| ~2021 | [data61/MP-SPDZ](https://github.com/data61/MP-SPDZ) | v0.2.0 | Fix: insufficient randomization of FKOS15 inputs; randomization mask was too narrow to achieve claimed statistical security |
| ~2021–2022 | [data61/MP-SPDZ](https://github.com/data61/MP-SPDZ) | v0.3.x | Fix: protocols with malicious security did not check players' inputs when generating random bits; bit shares not verified to lie in $\{0,1\}$ |
| Dec 24, 2024 | [data61/MP-SPDZ](https://github.com/data61/MP-SPDZ) | v0.4.2 / [commit `bf7f8f4`](https://github.com/data61/MP-SPDZ/commit/bf7f8f4b65e4653b5353fe652005319651794834) | Fix: minor security parameter degradation in HighGear input protocol; ring size off-by-one reduced effective $\sigma$ |

### Real-World Impact

**bnb-chain/tss-lib — unvalidated signing inputs (2019).** The tss-lib library is the foundational TSS implementation behind BNB Chain's custody infrastructure and was forked by numerous projects including THORChain, SwingBy, and others operating cross-chain bridges and MPC wallets. The missing $\mathbb{Z}_q$ message check and absent final-signature verification were identified in Kudelski Security's October 2019 audit. Although no on-chain exploit exploiting these specific checks has been publicly confirmed, the library was already deployed in production BNB Chain key management at the time the audit findings were disclosed. Any application that passed raw (unreduced) message bytes to the signing API before the v1.2.0 patch was potentially signing messages with malleable semantics.

**MP-SPDZ SPDZ2k input MAC — silent authentication bypass (2020).** The wrong-MAC-check bug in SPDZ2k input generation (fixed in v0.2.2) is particularly dangerous because it is silent: no runtime error or abort occurs. An adversary can inject inputs outside the intended domain and have them accepted as authenticated by all honest parties. SPDZ2k is used in applications where the computation ring $\mathbb{Z}_{2^k}$ must match a native machine integer type (e.g., 64-bit arithmetic), and deployments using it for privacy-preserving machine learning or financial computation would have been silently vulnerable to input poisoning attacks.

**MP-SPDZ random-bit generation (v0.3.x).** Random bits generated jointly by MPC parties are consumed in oblivious transfer extension, coin-flipping sub-protocols, and garbled circuit wire label selection. A malicious party that injects a non-bit share into the joint random-bit generation can bias these downstream values, potentially reducing the effective security of OT-based protocols from computational to statistical and leaking information about honest parties' inputs one bit at a time. This class of attack is subtle to detect because the biased outputs appear numerically valid and are accepted by all downstream protocol steps.

-->
