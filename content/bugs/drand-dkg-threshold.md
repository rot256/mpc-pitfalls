---
title: "Drand DKG Threshold Constraint"
date: 2020-11-26
primitives: [secret-sharing]
source:
  - name: "Sigma Prime, 2020"
    url: https://blog.sigmaprime.io/dkg-rogue-key.html
---

Drand is a distributed randomness beacon using DKG and threshold BLS, with a threshold above half the participants under its security model (see the [protocol specification](https://docs.drand.love/docs/specification)). With polynomial degree $t > n/2$, a coalition of at least $n - t + 1$ parties can mount a rogue-key attack: after seeing the honest parties' constant-term commitment ($A_{i,0} = g^{a_{i,0}}$), the colluding parties choose their own so the group public key becomes an attacker-chosen 
$Y^\star = g^{x^\star}$.

The proposed fix was using commit-before-reveal. Drand instead mitigated the issue by lowering the configured threshold closer to $n/2$, since the rogue-key attack would then require a coalition outside the honest-majority assumption.