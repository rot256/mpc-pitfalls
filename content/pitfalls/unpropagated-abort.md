---
title: "Abort Not Propagated to Parallel OT-Extension Instances"
class: failure-recovery-and-abort-handling
hidden: true
order: 3
source: "oblivious-transfer.md"
primitives: [oblivious-transfer]
---


<!--<div class="pitfall-flags"><span class="flag flag-tbd">TBD example</span></div>-->

**What can go wrong.** [DKLs23](https://eprint.iacr.org/2023/765.pdf) makes the
engineering obligation explicit: when an OT extension consistency check fails, the
implementation must abort **every** protocol instance running in parallel that
involves the same offending party. An abort that is local to a single instance —
however well-typed and however clearly identified — still leaves the other instances
running, each of which can continue leaking bits of the same base-OT state to the
same attacker.

**Security implication.** A malicious receiver opens $k$ concurrent OT extension
sessions against the same sender. The selective-abort probe in any single session
leaks one bit of $\Delta$. If the honest sender aborts only the offending session
(and not the other $k - 1$ sessions with the same peer), the attacker replays the
probe in the next session and gets the next bit. Across the $k$ sessions, the
attacker reconstructs $\Delta$ roughly $k$ times faster than with a single session —
and the per-session abort did not slow them down.

**How to avoid.** Track the offending party's identifier as part of a shared
session-state registry. When any session receives an `AbortProtocolAndBanReceiver`
(or equivalent) error naming a party, propagate that cancellation to every other
currently-running session that involves the same party. This is easier said than
done: it requires the library to have visibility into all concurrent sessions,
which in turn requires either a session manager above the OT extension API or a
convention that every session carries a cancellation token the caller can broadcast.

<!--**Example.** *TBD.* The DKLs23 paper raises this as an engineering concern; no public
CVE is pinned to a library that aborts its local session correctly but fails the
propagation step. In practice, the panic-style and opaque-error bugs above tend to
dominate because they prevent even local identifiable abort — once those are fixed,
the cross-session propagation becomes the next layer of defence.-->

**Example: NEAR Protocol `near/mpc` `multiplication_many` (zksecurity audit, open triage).**
The DKLs23-based threshold-ECDSA crate that powers NEAR's chain-abstraction MPC
node launches `N × (parties − 1)` OT multiplication tasks per pair via
`futures::future::try_join_all`, then collects the results indiscriminately
([source](https://github.com/near/mpc/blob/13804b7edbce47baa973d751a941bb930ebffd2d/crates/threshold-signatures/src/ecdsa/ot_based_ecdsa/triples/multiplication.rs#L172-L272)):

```rust
// crates/threshold-signatures/src/ecdsa/ot_based_ecdsa/triples/multiplication.rs
// near/mpc @ 13804b7e — multiplication_many
let mut tasks = Vec::with_capacity(participants.len() - 1);
for i in 0..N {
    for p in participants.others(me) {
        // ... build OT multiplication future for pair (me, p) at index i
        tasks.push(fut);
    }
}
// All N × (parties − 1) futures joined indiscriminately.
// On any failure, try_join_all cancels every sibling — not per-party,
// not atomically with respect to messages already in flight, and the
// surfaced ProtocolError carries no party identifier the caller could
// use to ban the offender.
let results = futures::future::try_join_all(tasks).await?;
```

The pattern violates the DKLs23 obligation that an OT consistency-check failure
must abort *all* parallel instances with the offending party atomically: once one
sub-task fails, the surviving sub-tasks involving the same peer race the
cancellation and may continue exchanging messages, leaking small amounts of OT
state. The error path also has no per-party identifier, so the orchestrator
cannot enforce a cross-session ban on the offender. zksecurity's audit
([finding_007](https://github.com/zksecurity/claude-bug-hunting/blob/master/near/threshold-signatures/C/finding_007.md))
recommends per-party cancellation tokens or sequential per-peer execution. The
finding is rated Low because the consistency check is batched (not per-bit) and
the race window is narrow, but it is a clean illustration of the engineering
pitfall in production code; manual triage is still in progress at the time of
writing.
