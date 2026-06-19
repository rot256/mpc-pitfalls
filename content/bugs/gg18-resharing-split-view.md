---
title: "GG18 resharing split-view attack"
date: 2021-04-08
primitives: [broadcast]
source:
  - name: "Kudelski, 2021"
    url: https://kudelskisecurity.com/research/audit-of-ings-threshold-ecdsa-library---and-a-dangerous-vulnerability-in-existing-gennaro-goldfeder18-implementations
---

Kudelski's audit of ING's threshold-ECDSA library identified a communication-layer
failure in the GG18 resharing protocol. The issue was a design-level mismatch: the
resharing mitigation relies on all honest parties seeing the same final confirmation,
but that assumption is not realized by sending separate point-to-point messages. ING
implemented the standard "forget-and-forgive" mitigation, a final ACK confirmation
round before parties delete their old shares; Kudelski noted that this mitigation
*"might actually make things worse"* if a robust broadcast channel is not available,
because the final ACK can itself be equivocated. If an application
realizes broadcast as $N$ separate point-to-point sends, a malicious sender can
equivocate.

Kudelski's example starts with four peers $(A, B, C, D)$ using a threshold of 3, and a
resharing ceremony that adds a fifth peer $E$ while keeping the threshold at 3. At the
end of the resharing protocol, malicious $E$ sends different final-round messages to
different honest parties:

- $E$ sends `ACK` to $A$ and $B$.
- $E$ sends `not ACK` to $C$ and $D$.

$A$ and $B$ believe resharing succeeded, discard their old shares, and migrate to the new
committee. $C$ and $D$ believe resharing failed, keep the old shares, and do not save the
new shares. The honest parties are now split between incompatible old and new committee
states. Neither honest subset has enough compatible shares to sign without $E$, so the
single malicious participant can lock the wallet.