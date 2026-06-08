---
title: "Missing Domain Separation When a Hash Function Is Reused"
class: cryptographic-primitives
hidden: false
order: 4
source: "hash-functions.md"
primitives: [hash, zkp]
bugs: [tss-lib-sha512-shared-hash]
display: [tss-lib-sha512-shared-hash]
---

**What can go wrong.** A single hash function is often reused across distinct purposes inside the same protocol: Fiat-Shamir challenges for different proofs, commitments, key derivation, session-ID generation, even signatures. When the same hash is invoked for these unrelated contexts without anything distinguishing them, it lets an adversary fraudulently pass off a hash output produced honestly in one context as valid in a different context.

**Security implication.** Without domain separation, a hash output has no
unambiguous meaning: the verifier cannot tell which protocol, proof type,
session, role, or statement it belongs to. This can enable replay across
sessions, cross-context confusion between related protocol steps, or
Fiat-Shamir challenges that bind less transcript data than the security proof
assumes. In threshold-signature implementations, these failures can let
adversarial transcripts verify in the wrong context.

**How to avoid.** Prepend a constant-length domain-separation tag, distinct per context, to every hash invocation. The tag should encode the protocol name, the specific proof or purpose inside the protocol, a session identifier, and typically a version number. 
