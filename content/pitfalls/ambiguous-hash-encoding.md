---
title: "Ambiguous Hash Encoding"
class: cryptographic-primitives
hidden: false
order: 5
source: "hash-functions.md"
primitives: [hash, zkp]
---


**What can go wrong.** Many protocols need to hash several values together, such as group elements, integers, or commitments. In the Fiat-Shamir transform, for example, the challenge is just the hash of the transcript. The naive encoding concatenates the values with a delimiter, $H(m_1 ,|, D ,|, m_2 ,|, \cdots ,|, D ,|, m_n)$, where $D$ is a fixed byte sequence such as `0x00` or `||`. This is not injective: because each $m_i$ is an arbitrary byte string that may itself contain $D$, two different input tuples can serialize to the same byte string, and therefore hash to the same value.

**Security implication.** Because the encoding is ambiguous, an adversary can shift boundaries around, manipulate which parts of the input get interpreted as which values, without changing the hash output. In the context of discrete log proofs, the adversary sends a single commitment stream whose bytes can be parsed several ways, all hashing to the same challenge. After observing the challenge bits, the adversary retroactively chooses the parse that makes the verification equation hold for every bit, producing a valid-looking proof of knowledge of a discrete log the adversary does not know. Applied to threshold-ECDSA signing, the adversary can forge the MtA range proofs, leading to recovery of other parties' secret shares and ultimately the shared key. The attack is documented by [Hexens](https://hexens.io/blog/mpc-attacks-p1) and catalogued as the [TSSHOCK α-shuffle attack](https://verichains.io/tsshock/).

**How to avoid.** Make the encoding injective: length-prefix each element with a fixed-width tag; an 8-byte little-endian length is enough. Better still, use the protocol's specified serialization format where one exists.
