---
title: "Missing Domain Separation When a Hash Function Is Reused"
class: cryptographic-primitives
hidden: false
order: 4
source: "hash-functions.md"
primitives: [hash, zkp]
---


**What can go wrong.** A single hash function is often reused across distinct purposes inside the same protocol: Fiat-Shamir challenges for different proofs, commitments, key derivation, session-ID generation, even signatures. When the same hash is invoked for these unrelated contexts without anything distinguishing them, it lets an adversary fraudulently pass off a hash output produced honestly in one context as valid in a different context.

**Security implication.** A Schnorr challenge hashed for one sub-protocol can satisfy the verification equation for another: a proof generated honestly under sub-protocol $A$'s statement is accepted as a proof under sub-protocol $B$'s statement. In threshold-signature implementations this lets the same proof bytes, produced for one context, be replayed as a proof for another.

**How to avoid.** Prepend a constant-length domain-separation tag, distinct per context, to every hash invocation. The tag should encode the protocol name, the specific proof or purpose inside the protocol, a session identifier, and typically a version number. 
<!--
Separately, encode the remaining hash inputs unambiguously, preferably with the protocol's specified serialization format. Injective encoding prevents distinct input tuples from colliding within a single context, blocking [$\alpha$-shuffle attacks](https://verichains.io/tsshock/).
-->
