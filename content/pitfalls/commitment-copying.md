---
title: "Rushing Adversary Copies an Honest Commitment"
class: lack-of-context-binding
hidden: false
order: 4
source: "commitments-not-bound.md"
primitives: [commitment, mac]
---


**What can go wrong.** In a commit-and-reveal protocol, each party sends a commitment
during round 1 and opens it during round 2. If the commitment scheme does not bind each commitment to the identity of its opener (for example, by hashing in the party's ID and
session ID), a rushing adversary, one who observes honest parties' messages before sending its own in the same round, can copy an honest party's commitment byte-for-byte,
then copy the opening during the reveal phase. Both parties end up revealing the same value.

**Security implication.** Consider a [Blum coinflip](https://www.zkdocs.com/docs/zkdocs/commitments/): Alice and Bob commit to random bits
$v_A, v_B$ and open to produce $v = v_A \oplus v_B$. A corrupt Bob who copies Alice's commitment, then copies her opening, makes $v_B = v_A$, so the output is always $v_A
\oplus v_A = 0$, the coin no longer flips. The same pattern breaks the SPDZ MAC-check sub-protocol in two-party settings: when parties commit to their $z_i$ shares and an
honest $P_1$'s commitment is copied, the reconstructed $z = z_1 + z_1 = 0$ and the MAC check passes for any opened value $a'$, defeating the integrity guarantee on every wire
of the circuit.

**How to avoid.** Bind every commitment to its opener's identity and to the session. Two standard constructions:

- **Hash-based commitment with opener ID and session ID**:
  $c_i = H(\text{pid}_i \,\|\, \text{ssid} \,\|\, v_i \,\|\, r_i)$.
  A copied commitment has the wrong `pid` and cannot be reopened consistently.
- **Signed commitment**: Contrary to the hash-based commitment, a signed
  commitment binds *only the PID* (through the signing key) and not the SSID.
  To bind both the *party and the session*, you may use one of the following:
  - Compute the signature  $s = \text{Sign}_{\text{sk}_i}(\text{ssid} \,\|\, c)$, where $c$ is the commitment and $\text{sk}_i$ is the signing key tied to the party.
  - Include the session ID inside the commitment,
    $c_i = \text{Commit}(\text{ssid} \,\|\, v_i \,\|\, r_i)$, and sign it with a
    key bound to the party. Here the commitment provides the session binding and
    the key provides the party binding.
  - Use a signing key uniquely bound to both the *party and the current session*. Note that this is quite unusual in practice, as long-term signing keys are typically preferred.

Either construction prevents the rushing-adversary copy because the opener's identity and the current session are now part of what the commitment binds to.
