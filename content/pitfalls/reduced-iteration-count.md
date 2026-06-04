---
title: "Insufficient Soundness from Reduced Iteration Count"
class: cryptographic-primitives
hidden: false
order: 3
source: "fiat-shamir.md"
primitives: [zkp]
bugs: [multichain-fastmpc-tsshock]
display: [multichain-fastmpc-tsshock]
---


**What can go wrong.** Some Fiat-Shamir-transformed proofs, such as the DLN proof of knowledge used in GG18/GG20/CGGMP21, reach their target soundness only by running many parallel challenge-response repetitions. If the iteration count is set such that the soundness error is high, an adversary can simply guess responses and convince the verifier without holding the claimed witness.

**Security implication.** An adversary brute-forces candidate proofs offline until one passes within the reduced soundness margin. DLN proofs in GG18 are repeated $k$ times and the soundness error is $2^{-k}$. So to forge a proof without knowing the discrete log, an attacker needs to guess all $k$ challenge bits, with a probability of $2^{-k}$. This is the [c-guess](https://verichains.io/tsshock/) attack as documented by Verichains. In Multichain's fork, $k$ was set as low as $k = 1$, where each attempt succeeds with probability $1/2$.

**How to avoid.** Keep the iteration count at the value the specification mandates: **at least 128** for CGGMP21 / GG18 / GG20 DLN proofs. If performance is the concern, switch to a compiled non-interactive proof instead of cutting rounds.