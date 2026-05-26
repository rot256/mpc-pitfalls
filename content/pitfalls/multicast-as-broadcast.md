---
title: "Multicast Masquerading as Broadcast"
class: insecure-subprotocol-instantiation
hidden: false
source: "uc-protocols.md"
primitives: [broadcast]
---

### Multicast Masquerading as Broadcast

**What Can Go Wrong.** MPC protocols such as [GG18](https://eprint.iacr.org/2019/114), [GG20](https://eprint.iacr.org/2020/540), and [FROST](https://eprint.iacr.org/2020/852) may rely on a *reliable broadcast channel* for some rounds, and are often implemented by instantiating the broadcast with *multicast*: simply having each party send the same message to all others over P2P links. Per [Goldwasser and Lindell, 2002](https://eprint.iacr.org/2002/040), *privacy* and *correctness* can be achieved without full broadcast by using *echo-broadcast* (receivers re-send what they got and abort on mismatch), at the cost of non-unanimous abort. But echo-broadcast only achieves "broadcast with abort": same value or $\bot$, never two different non-abort values, still strictly weaker than what these protocols assume in their published proofs. A library that cannot tell whether a given round was supposed to be broadcast or point-to-point cannot enforce reliable broadcast, and therefore cannot ensure *privacy* and *correctness*.

<!--If the application instantiates "broadcast" as a
loop of per-peer sends, a malicious sender can equivocate (send $v_1$ to one honest
party and $v_2$ to another) and no honest participant can detect the split.
Echo-broadcast (every party re-broadcasts what it received before accepting)
provides only single-round local consistency, not full Byzantine agreement, so a
malicious sender can shift the split into the second round.-->

**Security implication.** Honest parties end up with different views of the same round, which can cause them to compute incompatible outputs and break *correctness*. In threshold signing, equivocation in a DKG commitment round leaves honest parties disagreeing on the public key; in a zero-knowledge proof round, it can let an invalid proof pass for one verifier and fail for another.
<!--; in a final-confirmation or resharing round, it can split the honest set between incompatible committee states, locking funds permanently, as in the GG18 example below.-->

**How to avoid.** Implement a reliable broadcast protocol (not just echo-broadcast) for
any round whose security proof requires Byzantine agreement. In settings with fewer than
$n/3$ corruptions, Bracha broadcast provides the required guarantees. Enforce the
per-round broadcast-vs-P2P classification at the library boundary using the protocol
specification as reference, rather than delegating the decision to the caller.
