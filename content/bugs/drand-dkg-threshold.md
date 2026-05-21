---
title: "Drand DKG Threshold Constraint"
category: adaptive-inputs
subcategory: "Rogue-Key Attacks"
date: 2020-01-01
primitives: [secret-sharing]
source:
  - name: "Sigma Prime, 2020"
    url: https://blog.sigmaprime.io/dkg-rogue-key.html
hidden: false
---

Drand's [protocol specification](https://docs.drand.love/docs/specification) describes
it as a distributed randomness beacon using DKG and threshold BLS, with a threshold above
half the participants under its security model. Sigma Prime showed that
when the polynomial degree $t$ exceeds $n/2$ (that is, a $(t+1)$-of-$n$ reconstruction
threshold), a coalition of $m \ge n - t + 1$ parties can mount a rogue-key attack: after
seeing the honest parties' public commitments, the colluding parties choose their own
constant-term commitments so the final public key becomes an attacker-chosen
$Y^\star = g^x$. The attacker then knows the discrete log of the group public key.

The post proposes an initial hash commit-before-reveal phase over each party's polynomial
commitments, for example `Hash(A_{i,0} || A_{i,1} || ... || A_{i,t})`, before any
commitment values are revealed. Drand instead lowered the configured threshold closer to
$n/2$, so the rogue-key attack would require a coalition outside the assumed fault bound.
