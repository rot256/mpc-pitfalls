---
title: "Fresco `HashBasedCommitment`"
date: 2025-02-27
primitives: [commitment, mac]
repository: https://github.com/aicis/fresco
issue: 432
pr: 433
---

In the [SPDZ protocol](https://eprint.iacr.org/2011/535.pdf), parties hold
additive shares of a global SPDZ MAC $[\alpha \cdot a]$ on every wire under a
single global MAC key $\alpha$.
To verify that a reconstructed value $a'$ is correct, each party computes
$z_i = a' \cdot \alpha_i - (\alpha \cdot a)_i$, commits to $z_i$, and opens;
if the reconstructed $z = \sum z_i \ne 0$, they abort. SPDZ also uses the
same commitment scheme in coin-tossing and input-sharing subprotocols.

Fresco's `HashBasedCommitment` hashed only the value and the randomness,with no opener identity in the input, allowing a malicious party to replay it. Pre-fix `commit` method
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

Each party's commitment is $c_i = H(v_i \,\|\, r_i)$, with no opener identity in the
hash input. Fresco does not implement SPDZ over binary fields, so the
characteristic-2 single-MAC-check copy (where a copied $z_1$ gives $z = z_1 + z_1 = 0$)
does not apply to it directly. Fresco is instead hit through the same commitment's
use in coin-tossing: a corrupt party copies an honest party's seed commitment
$H(s_i \,\|\, r_i)$ byte-for-byte and later copies the opening $(s_i, r_i)$, so the
two identical seeds cancel in the XOR $s = s_1 \oplus \cdots \oplus s_n$. This strips
the honest party's entropy from the tossed coin, making it adversarially predictable
and letting the corrupt party pass the batch MAC check on inconsistent values. The fix ([PR #433](https://github.com/aicis/fresco/pull/433)) added the committer's party ID as the first input to the hash
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