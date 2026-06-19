---
title: "Selective-Abort Attacks during OT Extension"
class: failure-recovery-and-abort-handling
hidden: false
order: 1
source: "oblivious-transfer.md"
primitives: [oblivious-transfer]
bugs: [trailofbits-ot-extension-selective-abort, lindell17-abort-handling]
display: [trailofbits-ot-extension-selective-abort]
---

**What can go wrong.** OT-extension protocols ([Ishai et al., 2003](https://csaws.cs.technion.ac.il/~erez/Papers/IsKiNiPe-Crypto03.pdf)) are made secure against a malicious receiver by a *consistency check* ([Keller-Orsini-Scholl, 2015](https://eprint.iacr.org/2015/546)), in which the sender validates the receiver's queries against its own secret choices. It is no silver bullet: the check is computed from those choices, so whether it passes or fails leaks one bit of them, letting a cheating receiver force a *selective* abort to learn a bit of the secret. A single failure may not leak much, and the protocol stays secure as long as a failed check is treated as terminal and the base OT discarded. But if the implementation keeps the setup alive after a failure, for example behind an opaque error the sender simply retries, the receiver reconstructs the secret bit by bit across many calls.

**Security implication.** An attacker selectively forces an abort to learn one bit of the sender's secret choices, then repeats the procedure over different executions that reuse the same base OTs. Eventually it learns every secret bit, breaking security. In a threshold signature scheme this lets an attacker recover the signing key, and with more parties the attacker repeats the process against each one.

**How to avoid.** Exclude the corrupted party, discard the OTs on which the adversary gained leakage, and resample fresh base OTs before continuing. In case of parallel OT-extension instances, replicate this across all instances. The correlation check of [KOS 2015](https://eprint.iacr.org/2015/546) keeps the per-run leakage negligible but does not by itself prevent selective-abort attacks, so the no-reuse discipline above is what actually stops full key recovery.

A closely related selective-abort attack also appears outside OT extension, in Paillier-based two-party ECDSA such as the Lindell17 abort-handling bug, where the abort signal leaks one bit of the honest party's share per signing attempt. The mechanism is different (no OT is involved), but the same lesson holds: a failed check must be terminal, never a silent retry.