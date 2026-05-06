---
title: "Rushing adversary copies an honest commitment"
class: "Lack of Binding to Execution Context"
source: "commitments-not-bound.md"
---

### Rushing adversary copies an honest commitment

**What can go wrong.** In a commit-and-reveal protocol, each party sends a commitment
during round 1 and opens it during round 2. If the commitment scheme does not bind each
commitment to the identity of its opener (for example, by hashing in the party's ID and
session ID), a rushing adversary — one that observes honest parties' messages before
sending its own in the same round — can copy an honest party's commitment byte-for-byte,
then copy the opening during the reveal phase. Both parties end up revealing the same
value.

**Security implication.** Consider a Blum coinflip: Alice and Bob commit to random bits
$v_A, v_B$ and open to produce $v = v_A \oplus v_B$. A corrupt Bob who copies Alice's
commitment, then copies her opening, makes $v_B = v_A$, so the output is always $v_A
\oplus v_A = 0$ — the coin no longer flips. The same pattern breaks the SPDZ MAC-check
sub-protocol in two-party settings: when parties commit to their $z_i$ shares and an
honest $P_1$'s commitment is copied, the reconstructed $z = z_1 + z_1 = 0$ and the MAC
check passes for any opened value $a'$, defeating the integrity guarantee on every wire
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

**Example: Fresco SPDZ MAC check (`SpdzMacCheckProtocol`).** In the
[SPDZ protocol](https://eprint.iacr.org/2011/535.pdf), parties hold BDOZ MACs
$[\alpha \cdot a]$ on every wire under a global MAC key $\alpha$. To verify that a
reconstructed value $a'$ is correct, each party computes
$z_i = a' \cdot \alpha_i - (\alpha \cdot a)_i$, commits to $z_i$, and opens; if the
reconstructed $z = \sum z_i \ne 0$, they abort.

Fresco's implementation used a plain hash-based commitment ([source](https://github.com/aicis/fresco/commit/fdada93b1abf19c68a1cf744e0f294df86bb1b8f)):

```java
// FILE: HashBasedCommitment.java — Fresco (vulnerable)
public byte[] commit(Drbg rand, byte[] value) {
    if (commitmentVal != null) {
        throw new IllegalStateException("Already committed");
    }
    byte[] randomness = new byte[DIGEST_LENGTH];
    rand.nextBytes(randomness);
    byte[] openingInfo = new byte[value.length + randomness.length];
    System.arraycopy(value, 0, openingInfo, 0, value.length);
    System.arraycopy(randomness, 0, openingInfo, value.length, randomness.length);
    commitmentVal = digest.digest(openingInfo);  // no party ID in hash input
    return openingInfo;
}
```

Each party's commitment is $c_i = H(z_i \,\|\, r_i)$ — no opener identity in the hash
input. In a two-party setting over $\mathbb{F}_{2^k}$, the corrupt party copies the honest
$P_1$'s commitment, then copies the opening $(z_1, r_1)$. The reconstructed
$z = z_1 + z_1 = 0$ and the MAC check passes regardless of what $a'$ was reconstructed,
breaking the MAC's integrity guarantee.
