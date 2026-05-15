---
title: "Multicast Masquerading as Broadcast"
class: insecure-subprotocol-instantiation
source: "uc-protocols.md"
---

### Multicast Masquerading as Broadcast

**What can go wrong.** Many MPC protocol proofs are written in the
*Universal Composability* (UC) framework of
[Canetti (2001)](https://eprint.iacr.org/2000/067), which models the broadcast
channel as an ideal functionality $\mathcal{F}_{\text{BC}}$: in a given round, every
honest party receives the same message from the sender. Threshold protocols
including [GG18](https://eprint.iacr.org/2019/114) and
[GG20](https://eprint.iacr.org/2020/540) for ECDSA and
[FROST](https://eprint.iacr.org/2020/852) for Schnorr explicitly require this
functionality for at least one round of key generation or signing. Realizing
$\mathcal{F}_{\text{BC}}$ over an asynchronous network requires a *reliable
broadcast* protocol such as [Bracha (1987)](https://www.sciencedirect.com/science/article/pii/089054018790054X),
which provides Byzantine agreement against $t < n/3$ corruptions. A library that
cannot tell whether a given round was supposed to be broadcast or point-to-point
cannot enforce that assumption. If the application instantiates "broadcast" as a
loop of per-peer sends, a malicious sender can equivocate (send $v_1$ to one honest
party and $v_2$ to another) and no honest participant can detect the split.
Echo-broadcast (every party re-broadcasts what it received before accepting)
provides only single-round local consistency, not full Byzantine agreement, so a
malicious sender can shift the split into the second round.

**Security implication.** Honest parties end up with different views of the same
protocol round. The composition-level guarantee the UC proof relied on (that the round
fixed a single value across all honest views) no longer holds, and subsequent rounds
run on diverging state. In threshold signing the practical consequences include
key-generation concluding with honest parties disagreeing on the public key, silent
denial-of-service by a single adversary, and (depending on which round is attacked)
share exposure, proof forgeries, or permanently-inconsistent key material.

**How to avoid.** Implement a reliable broadcast protocol (not just echo-broadcast) for
any round whose security proof requires Byzantine agreement. In settings with fewer than
$n/3$ corruptions, Bracha broadcast provides the required guarantees. Enforce the
per-round broadcast-vs-P2P classification at the library boundary using the protocol
specification as reference, rather than delegating the decision to the caller.

**Example: GG18 resharing split-view attack ([Kudelski, 2021](https://kudelskisecurity.com/research/audit-of-ings-threshold-ecdsa-library---and-a-dangerous-vulnerability-in-existing-gennaro-goldfeder18-implementations)).**
Kudelski's audit of ING's threshold-ECDSA library identified a communication-layer
failure in the GG18 resharing protocol. The issue was a design-level mismatch: the
resharing mitigation relies on all honest parties seeing the same final confirmation,
but that assumption is not realized by sending separate point-to-point messages. ING
attempted echo-broadcast as the mitigation; Kudelski noted it *"might actually make
things worse"* without a true reliable-broadcast layer underneath. If an application
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
single malicious participant can lock the wallet and blackmail the rest of the committee.

The attack is exactly the multicast-as-broadcast failure: every honest party received a
message from $E$, but they did not receive the same message. The fix is not another local
validation check inside the resharing round; the deployment needs a broadcast mechanism
that gives all honest parties a consistent view of whether the final confirmation was sent.
