---
title: "Challenge Hash Missing Prover's Party Identity and Session Identifier"
class: lack-of-context-binding
hidden: false
order: 1
source: "zk-proofs-not-bound.md"
primitives: [zkp]
bugs: [tss-lib-schnorr-pok]
display: [tss-lib-schnorr-pok]
---


**What can go wrong.** In the Fiat-Shamir transformation, the verifier's challenge is replaced by a challenge hash that, in the single-prover, single-session case, depends only on the public statement and the prover's commitment. In a multi-prover or multi-session setting this is not enough, and the hash must also bind to the prover's party identifier (`pid`) and to the session identifier (`ssid`). If the `pid` is missing, nothing in the hash input identifies which prover computed it, so honest $P_i$ and malicious $P_m$ obtain the same challenge on the same statement and commitment within a single session. A proof $\pi_i$ produced by $P_i$ can then be replayed verbatim by $P_m$, who claims knowledge of the underlying witness without ever holding it. If the `ssid` is missing, the hash produces the same challenge value across every session running the same statement. Two invocations of the proof, one in key-generation session $A$ and another in signing session $B$, differ only in the surrounding protocol context, which the hash does not see. The proof bytes from session $A$ therefore remain structurally valid in session $B$, allowing replay across sessions.

**Security implication.** In a DKG (Distributed Key Generation) protocol, a malicious party $P_m$ can adaptively choose its public-key to match an honest party $P_i$'s ($X_m = X_i$). The malicious party then records $P_i$'s Schnorr proof and submits it as its own round contribution, passing the proof-of-knowledge check without holding any secret. The malicious party can also reuse it in later sessions.

**How to avoid.** Include the prover's party identifier (`pid`, public key, or
protocol-assigned role) in every FS challenge hash and derive a session identifier ssid from every public parameter of the current run. In practice many libraries fold the party identifier into the `ssid` derivation (the participant set is included in `ssid`).