---
title: "Rushing Adversary Copies an Honest Commitment"
class: lack-of-context-binding
hidden: false
source: "commitments-not-bound.md"
primitives: [commitment, mac]
---

### Rushing Adversary Copies an Honest Commitment

**What can go wrong.** In a commit-and-reveal protocol, each party sends a commitment
during round 1 and opens it during round 2. If the commitment scheme does not bind each commitment to the identity of its opener (for example, by hashing in the party's ID and
session ID), a rushing adversary, one who observes honest parties' messages before sending its own in the same round, can copy an honest party's commitment byte-for-byte,
then copy the opening during the reveal phase. Both parties end up revealing the same value.

**Security implication.** Consider a [Blum coinflip](https://www.zkdocs.com/docs/zkdocs/commitments/): Alice and Bob commit to random bits
$v_A, v_B$ and open to produce $v = v_A \oplus v_B$. A corrupt Bob who copies Alice's commitment, then copies her opening, makes $v_B = v_A$, so the output is always $v_A
\oplus v_A = 0$, the coin no longer flips. The same pattern breaks the SPDZ MAC-check sub-protocol in two-party settings: when parties commit to their $z_i$ shares and an
honest $P_1$'s commitment is copied, the reconstructed $z = z_1 + z_1 = 0$ and the MAC check passes for any opened value $a'$, defeating the integrity guarantee on every wire
of the circuit.

**How to avoid.** Bind every commitment to its opener's identity (and to the session).
Two standard constructions:

- **Hash-based commitment with opener ID and session ID**:
  $c_i = H(\text{pid}_i \,\|\, \text{ssid} \,\|\, v_i \,\|\, r_i)$.
  A copied commitment has the wrong `pid` and cannot be reopened consistently.
- **Signed commitment**: attach a signature over the commitment with a key uniquely
  tied to the opener; a copied commitment fails signature verification.

Either construction prevents the rushing-adversary copy because the opener's identity is
now part of what the commitment binds to.

<!--
**Example: Fresco `HashBasedCommitment` ([Issue #432](https://github.com/aicis/fresco/issues/432), [PR #433](https://github.com/aicis/fresco/pull/433), commit
[`fdada93b`](https://github.com/aicis/fresco/commit/fdada93b1abf19c68a1cf744e0f294df86bb1b8f)).** In the
[SPDZ protocol](https://eprint.iacr.org/2011/535.pdf), parties hold BDOZ MACs
$[\alpha \cdot a]$ on every wire under a global MAC key $\alpha$. To verify that a
reconstructed value $a'$ is correct, each party computes
$z_i = a' \cdot \alpha_i - (\alpha \cdot a)_i$, commits to $z_i$, and opens; if the
reconstructed $z = \sum z_i \ne 0$, they abort. SPDZ also uses the same commitment scheme
in coin-tossing and input-sharing subprotocols.

Fresco's `HashBasedCommitment` hashed only the value and the randomness, with no opener
identity in the input, allwoing a malicious party to replay it.
Pre-fix `commit` method
([source](https://github.com/aicis/fresco/blob/2dc80dca1f9dca65a0d5590daab5fa67c02035d6/tools/commitment/src/main/java/dk/alexandra/fresco/tools/commitment/HashBasedCommitment.java#L53-L67)):

```java
// FILE: tools/commitment/src/main/java/dk/alexandra/fresco/tools/commitment/HashBasedCommitment.java
// aicis/fresco @ 2dc80dca (vulnerable, pre-PR #433)

public byte[] commit(Drbg rand, byte[] value) {
  if (commitmentVal != null) {
    throw new IllegalStateException("Already committed");
  }
  // Sample a sufficient amount of random bits
  byte[] randomness = new byte[DIGEST_LENGTH];
  rand.nextBytes(randomness);
  // Construct an array to contain the bytes to hash
  byte[] openingInfo = new byte[value.length + randomness.length];
  System.arraycopy(value, 0, openingInfo, 0, value.length);
  System.arraycopy(randomness, 0, openingInfo, value.length,
      randomness.length);
  commitmentVal = digest.digest(openingInfo);
  return openingInfo;
}
```

Each party's commitment is $c_i = H(z_i \,\|\, r_i)$, with no opener identity in the
hash input. In a two-party SPDZ MAC check over $\mathbb{F}_{2^k}$, a corrupt $P_2$ copies
$P_1$'s commitment byte-for-byte, then copies the opening $(z_1, r_1)$. Because the
field has characteristic 2, the reconstructed $z = z_1 + z_1 = 0$ and the MAC check
passes regardless of what $a'$ was reconstructed, breaking the MAC's integrity guarantee
on every wire of the circuit. The fix ([PR #433](https://github.com/aicis/fresco/pull/433), commit
[`fdada93b`](https://github.com/aicis/fresco/commit/fdada93b1abf19c68a1cf744e0f294df86bb1b8f),
merged February 27, 2025) added the committer's party ID as the first input to the hash
and required the opener to supply a matching ID at open time
([source](https://github.com/aicis/fresco/blob/fdada93b1abf19c68a1cf744e0f294df86bb1b8f/tools/commitment/src/main/java/dk/alexandra/fresco/tools/commitment/HashBasedCommitment.java#L63-L78)):

```java
// FILE: tools/commitment/src/main/java/dk/alexandra/fresco/tools/commitment/HashBasedCommitment.java
// aicis/fresco @ fdada93b (fixed)

public byte[] commit(int myId, Drbg rand, byte[] value) {
  if (commitmentVal != null) {
    throw new IllegalStateException("Already committed");
  }
  byte[] randomness = new byte[DIGEST_LENGTH];
  rand.nextBytes(randomness);
  // Party ID is now the first ID_LENGTH bytes of the hashed input.
  byte[] openingInfo = new byte[ID_LENGTH + value.length + randomness.length];
  System.arraycopy(integerToBytes(myId), 0, openingInfo, 0, ID_LENGTH);
  System.arraycopy(value, 0, openingInfo, ID_LENGTH, value.length);
  System.arraycopy(randomness, 0, openingInfo, value.length + ID_LENGTH,
      randomness.length);
  commitmentVal = digest.digest(openingInfo);
  return openingInfo;
}
```

-->
