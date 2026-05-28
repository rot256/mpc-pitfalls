---
title: "DLN-Proof Bases with Order 2 or 4 Accepted"
class: input-validation
hidden: true
source: "rsa-moduli.md"
primitives: [zkp, commitment, paillier, homomorphic-encryption]
---

### DLN-Proof Bases with Order 2 or 4 Accepted

**What can go wrong.** GG18/GG20 range proofs instantiate Pedersen commitments under
auxiliary bases $h_1, h_2 \in \mathbb{Z}_{\tilde N}^*$ and assume those bases generate
the same large subgroup. If an honest party accepts $h_1, h_2$ from a peer without any
cryptographic guarantee that neither base has small order, a malicious peer can supply
$h_1 = -1 \bmod \tilde N$ (order 2) or a small-order $h_2$. Pedersen commitments
$h_1^x h_2^r$ then collapse to $(-1)^x h_2^r$, leaking the parity of $x$ per
ciphertext; higher-order small bases leak more bits per use.

**Security implication.** An adversary chooses $h_1$ of order 2 and submits it as
auxiliary keygen input. In each subsequent signing MtA call, the range proof's
Pedersen commitment leaks $x \bmod 2$ of the victim's key share. By iterating with
crafted bases of increasing small order (2, 4, 8, …), the adversary reconstructs the
full share bit by bit. A degenerate variant provides $\tilde N = h_1 = h_2 = 1$,
making every range proof trivially verifiable — the adversary can claim any witness.

**How to avoid.** Accompany every $(h_1, h_2, \tilde N)$ broadcast with a **DLN proof**
that the sender knows $\alpha$ with $h_2 = h_1^{\alpha} \bmod \tilde N$, plus a
companion proof in the reverse direction ($h_1 = h_2^{\beta} \bmod \tilde N$). The
proof's soundness forces $h_1$ and $h_2$ to generate the same large subgroup, ruling
out small-order choices. Additionally require $h_1 \ne h_2$, and check that $\tilde N$
is at least a standard size (typically 2048 bits). For the modulus itself, see the
next mini-pitfall.

**Example: tss-lib CVE-2020-12118 — no DLN proofs in keygen.** In `bnb-chain/tss-lib`
before v1.2.0, round 2 of ECDSA keygen stored $h_1, h_2, \tilde N$ directly from the
incoming message without any proof
([source](https://github.com/bnb-chain/tss-lib/pull/89)):

```go
// FILE: ecdsa/keygen/round_2.go — bnb-chain/tss-lib < v1.2.0 (vulnerable)
for j, msg := range round.temp.kgRound1Messages {
    r1msg := msg.Content().(*KGRound1Message)
    round.save.PaillierPKs[j] = r1msg.UnmarshalPaillierPK()
    round.save.NTildej[j]     = r1msg.UnmarshalNTilde()           // ← no proof
    round.save.H1j[j], round.save.H2j[j] = r1msg.UnmarshalH1(), r1msg.UnmarshalH2()  // ← no proof
    round.temp.KGCs[j]        = r1msg.UnmarshalCommitment()
}
```

[PR #89](https://github.com/bnb-chain/tss-lib/pull/89) (merged March 5, 2020, released
as v1.2.0) added a `DlnProofVerifier` that runs two concurrent DLN proof checks
before accepting any party's bases:

```go
// FILE: ecdsa/keygen/round_2.go — bnb-chain/tss-lib >= v1.2.0 (fixed)
dlnVerifier := NewDlnProofVerifier(round.Concurrency())
for j, msg := range round.temp.kgRound1Messages {
    r1msg := msg.Content().(*KGRound1Message)
    H1j, H2j := r1msg.UnmarshalH1(), r1msg.UnmarshalH2()
    NTildej  := r1msg.UnmarshalNTilde()
    dlnVerifier.VerifyDLNProof1(round.temp.ssid, r1msg, H1j, H2j, NTildej,
        func(isValid bool) { /* abort if false */ })
    dlnVerifier.VerifyDLNProof2(round.temp.ssid, r1msg, H2j, H1j, NTildej,
        func(isValid bool) { /* abort if false */ })
    // Also check Paillier modulus is 2048 bits and h1 != h2
}
```

For the complementary concern that the factors of $\tilde N$ themselves must be safe
primes (otherwise even a sound DLN proof can be forged once the factorization is
smooth), see the [Discrete Log Groups](../discrete-log-groups/) pitfall.
