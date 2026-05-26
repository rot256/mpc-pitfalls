---
title: "tss-lib DLN bases without proofs or bounds"
category: input-validation
subcategory: "Group Elements Not Validated in Discrete-Log Groups"
order: 1
date: 2020-03-05
primitives: [paillier, homomorphic-encryption, zkp, commitment, group]
repository: https://github.com/bnb-chain/tss-lib
pr: 89
cve:
  name: CVE-2020-12118
  url: https://nvd.nist.gov/vuln/detail/CVE-2020-12118
source:
  - name: "Trail of Bits TOB-BIN-8 fix"
    url: https://github.com/bnb-chain/tss-lib/commit/c0a1d4e4a1
hidden: false
---

GG18/GG20 range proofs instantiate Pedersen commitments under auxiliary bases
$h_1, h_2 \in \mathbb{Z}_{\tilde N}^*$ and assume those bases generate the
same large subgroup. Two successive bugs hit the tss-lib library on this exact
surface.

**Original keygen broadcast ships bases with no DLN proof at all.** Round 2
of ECDSA keygen stored the incoming triple $(\tilde N, h_1, h_2)$ directly,
with no validation
([source](https://github.com/bnb-chain/tss-lib/blob/6584db7f6f6bee1707ba4f6b06c4aabccbbb3ed7/ecdsa/keygen/round_2.go#L26-L30)):

```go
// FILE: ecdsa/keygen/round_2.go
// bnb-chain/tss-lib @ 6584db7f (pre-PR #89, vulnerable)
for j, msg := range round.temp.kgRound1Messages {
    r1msg := msg.Content().(*KGRound1Message)
    round.save.PaillierPKs[j] = r1msg.UnmarshalPaillierPK() // used in round 4
    round.save.NTildej[j] = r1msg.UnmarshalNTilde()
    round.save.H1j[j], round.save.H2j[j] = r1msg.UnmarshalH1(), r1msg.UnmarshalH2()
    // ...
}
```

A malicious peer sets $h_1 = \tilde N - 1$ (order 2 in
$\mathbb{Z}_{\tilde N}^*$); each subsequent MtA range-proof commitment
$h_1^x h_2^r = (-1)^x h_2^r$ leaks the parity of the victim's key share per
ciphertext. When $\tilde N$ is generated without enforcing safe primes (see
[non-safe-prime modulus](../pitfalls/non-safe-prime-modulus.md)),
$\phi(\tilde N)$ has additional small factors and iterating with bases of
order 4, 8, ... reconstructs the full share via Pohlig-Hellman and CRT. A
degenerate variant ships $\tilde N = h_1 = h_2 = 1$, making every range proof
trivially verifiable so the adversary can claim any witness.

[PR #89](https://github.com/bnb-chain/tss-lib/pull/89) (merged March 5, 2020,
released as v1.2.0) wraps the same loop with a $h_1 \ne h_2$ guard, a
uniqueness check on $h_1, h_2$ across parties, and two concurrent DLN proof
verifications before any party's bases are accepted. The verification core
([`ecdsa/keygen/round_2.go#L51-L62` @ `c66e035b`](https://github.com/bnb-chain/tss-lib/blob/c66e035bc1d25ceb1fd4dbf08a8f1a3bae3c4402/ecdsa/keygen/round_2.go#L51-L62)):

```go
// FILE: ecdsa/keygen/round_2.go (lines 51-62)
// bnb-chain/tss-lib @ c66e035b (post-PR #89, v1.2.0+)
go func(j int, msg tss.ParsedMessage, r1msg *KGRound1Message, H1j, H2j, NTildej *big.Int) {
    if dlnProof1, err := r1msg.UnmarshalDLNProof1(); err != nil || !dlnProof1.Verify(H1j, H2j, NTildej) {
        dlnProof1FailCulprits[j] = msg.GetFrom()
    }
    wg.Done()
}(j, msg, r1msg, H1j, H2j, NTildej)
go func(j int, msg tss.ParsedMessage, r1msg *KGRound1Message, H1j, H2j, NTildej *big.Int) {
    if dlnProof2, err := r1msg.UnmarshalDLNProof2(); err != nil || !dlnProof2.Verify(H2j, H1j, NTildej) {
        dlnProof2FailCulprits[j] = msg.GetFrom()
    }
    wg.Done()
}(j, msg, r1msg, H1j, H2j, NTildej)
```

**Follow-on: `Verify` itself accepted degenerate $h_1, h_2$ (Trail of Bits
TOB-BIN-8).** Even with DLN proofs verified at keygen, the `Verify` routine
inside `crypto/dlnproof/proof.go` ran the Sigma-protocol equation checks
without any sanity on the inputs themselves. It accepted $h_1, h_2 \in \{0,
1, \tilde N - 1\}$ or $h_1 = h_2$, and likewise accepted arbitrary $T[i],
\mathrm{Alpha}[i]$
([`crypto/dlnproof/proof.go#L52-L74` @ `c65c3564`](https://github.com/bnb-chain/tss-lib/blob/c65c35640cd679eceb076ec9e4762edf9030b7c5/crypto/dlnproof/proof.go#L52-L74)):

```go
// FILE: crypto/dlnproof/proof.go
// bnb-chain/tss-lib @ c65c3564 (pre-TOB-BIN-8, vulnerable)
func (p *Proof) Verify(h1, h2, N *big.Int) bool {
    if p == nil {
        return false
    }
    modN := common.ModInt(N)
    msg := append([]*big.Int{h1, h2, N}, p.Alpha[:]...)
    c := common.SHA512_256i(msg...)
    // ... Iterations rounds of Sigma-protocol equation checks ...
    return true
}
```

The TOB-BIN-8 fix
([commit `c0a1d4e4`](https://github.com/bnb-chain/tss-lib/commit/c0a1d4e4a168a7f7d9b3f1a20d449effab740c65),
[`crypto/dlnproof/proof.go#L56-L104` @ `c0a1d4e4`](https://github.com/bnb-chain/tss-lib/blob/c0a1d4e4a168a7f7d9b3f1a20d449effab740c65/crypto/dlnproof/proof.go#L56-L104))
added bounds checks for $h_1, h_2$ in $(1, \tilde N)$, the $h_1 \ne h_2$
guard, and matching per-element bounds on every entry of $T[]$ and $\mathrm{Alpha}[]$:

```go
// FILE: crypto/dlnproof/proof.go
// bnb-chain/tss-lib @ c0a1d4e4 (fixed, TOB-BIN-8)
func (p *Proof) Verify(h1, h2, N *big.Int) bool {
    if p == nil {
        return false
    }
    if N.Sign() != 1 {
        return false
    }
    modN := common.ModInt(N)
    h1_ := new(big.Int).Mod(h1, N)
    if h1_.Cmp(one) != 1 || h1_.Cmp(N) != -1 {
        return false
    }
    h2_ := new(big.Int).Mod(h2, N)
    if h2_.Cmp(one) != 1 || h2_.Cmp(N) != -1 {
        return false
    }
    if h1_.Cmp(h2_) == 0 {
        return false
    }
    for i := range p.T {
        a := new(big.Int).Mod(p.T[i], N)
        if a.Cmp(one) != 1 || a.Cmp(N) != -1 {
            return false
        }
    }
    for i := range p.Alpha {
        a := new(big.Int).Mod(p.Alpha[i], N)
        if a.Cmp(one) != 1 || a.Cmp(N) != -1 {
            return false
        }
    }
    // ... Sigma-protocol equation checks (Iterations rounds) unchanged ...
    return true
}
```

TOB-BIN-8 is a Trail of Bits finding identifier from a private audit of
BNB Chain's tss-lib; the audit report itself was not released publicly. The
fix and discussion are visible in
[PR #180](https://github.com/bnb-chain/tss-lib/pull/180) (merged into v1.3.5,
[release notes](https://github.com/bnb-chain/tss-lib/releases/tag/v1.3.5) explicitly
cite the finding ID).

Together, PR #89 closes the "paired bases of equal subgroup order" failure
mode via DLN proofs, and TOB-BIN-8 closes the bounds half of the
"subgroup-membership for received bases" failure mode. A full
$h^q \equiv 1 \pmod{\tilde N}$ membership check is the textbook minimum
guarantee that the bases lie in the intended subgroup; here the DLN proofs
play that role indirectly via soundness, conditional on $\tilde N$ being a
product of safe primes.
