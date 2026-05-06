---
title: "Multicast masquerading as broadcast"
class: "Insecure Subprotocol Instantiation"
source: "uc-protocols.md"
---

### Multicast masquerading as broadcast

**What can go wrong.** UC proofs of MPC protocols are written against idealized
communication channels, in particular a *reliable broadcast* channel in which every
honest party receives the same message from the sender in a given round. A library
that cannot tell whether a given round was supposed to be broadcast or point-to-point
cannot enforce that assumption. If the application instantiates "broadcast" as a loop
of per-peer sends, a malicious sender can equivocate (send $v_1$ to one honest party
and $v_2$ to another) and no honest participant can detect the split. Echo-broadcast —
every party re-broadcasts what it received before accepting — provides only
single-round local consistency, not full Byzantine agreement, so a malicious sender
can shift the split into the second round.

**Security implication.** Honest parties end up with different views of the same
protocol round. The composition-level guarantee the UC proof relied on (that the round
fixed a single value across all honest views) no longer holds, and subsequent rounds
run on diverging state. In threshold signing the practical consequences include
key-generation concluding with honest parties disagreeing on the public key, silent
denial-of-service by a single adversary, and — depending on which round is attacked —
share exposure, proof forgeries, or permanently-inconsistent key material.

**How to avoid.** Implement a reliable broadcast protocol (not just echo-broadcast) for
any round whose security proof requires Byzantine agreement. In settings with fewer than
$n/3$ corruptions, Bracha broadcast provides the required guarantees. Enforce the
per-round broadcast-vs-P2P classification at the library boundary using the protocol
specification as reference, rather than delegating the decision to the caller.

**Example: tss-lib `ParseWireMessage`.** The library's sole entry-point for inbound
messages delegates the broadcast/P2P decision entirely to the application layer
([source](https://github.com/bnb-chain/tss-lib/blob/master/tss/wire.go)):

```go
// FILE: tss/wire.go — bnb-chain/tss-lib (all versions)

func ParseWireMessage(wireBytes []byte, from *PartyID, isBroadcast bool) (ParsedMessage, error) {
    wire := new(MessageWrapper)
    wire.IsBroadcast = isBroadcast  // set by caller — library never validates this
    // ...
}
```

The library never cross-checks whether the round that generated `wireBytes` is
specified by the protocol to be a broadcast or a P2P round. Two failure modes feed off
this. *Sender equivocation*: a malicious sender $P_m$ sends $v_1$ to one honest party
and $v_2$ to another during a round whose security proof assumed reliable broadcast; if
the application instantiated "broadcast" as a loop of P2P sends, nothing catches the
inconsistency. *Classification mismatch*: two honest receivers whose transport layers
classify the same wire bytes differently end up with diverging protocol state — one
treats a value as globally agreed upon, the other as a personal P2P message.

Downstream projects including [THORChain TSS](https://github.com/thorchain/tss),
[Swingby Skybridge](https://github.com/SwingbyProtocol/tss-lib), and
[Keep Network](https://github.com/keep-network/keep-core) all deployed `tss-lib` without
implementing a reliable broadcast layer, inheriting this exposure. The library itself
has not changed this API as of v2.0.0: `tss/wire.go` is unchanged since August 2021 and
no reliable-broadcast implementation exists in the tree.
