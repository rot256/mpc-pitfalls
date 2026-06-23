---
title: "Rogue-Key Attacks"
class: adaptive-inputs
hidden: false
order: 1
source: "feldman-vss.md"
primitives: [secret-sharing, zkp, signature, commitment]
bugs: [drand-dkg-threshold]
display: [drand-dkg-threshold]
---


**What can go wrong.** A *distributed key generation* (DKG) protocol lets $n$ parties jointly produce a public key whose corresponding secret is shared among them, with no trusted dealer. In a Feldman-based DKG, each party $P_i$ broadcasts $A_{i,0} = g^{a_{i,0}}$, which is a commitment to its secret contribution $a_{i,0}$.  A shared public key is then defined as $Y = \prod_i A_{i,0}$. If the protocol neither requires parties to commit to their first-round messages before seeing others' contributions nor requires each party to prove knowledge of $a_{i,0}$, a malicious party or coalition may wait to see the honest parties' commitments and then choose its public contribution as a function of theirs. 

Note that at the aggregate-key level, this lets the attacker try to force the shared public key to be a key it controls. In a full Joint-Feldman DKG, the malicious contribution must also pass share verification, which is why the concrete Drand attack below requires a coalition in the relevant threshold regime.

**Security implication.** Let $Y^\star = g^x$ be the adversary's target (a key for
which it holds the discrete log $x$). After observing
$A_{1,0}, \dots, A_{n-1,0}$, $P_m$ announces $A_{m,0} = Y^\star \cdot
\left(\prod_{i \ne m} A_{i,0}\right)^{-1}$. Multiplying all commitments yields
$\prod_i A_{i,0} = Y^\star$. The shared "threshold" key is now under $P_m$'s sole
control.

_Note: Joint-Feldman DKG typically assumes an honest majority within $n$ parties, so corrupting more than $n/2$ is taken to be out of scope. The attack requires a coalition of at least $n - t + 1$ malicious users, which exceeds $n/2$ when $t \le n/2$ and falls outside the assumed fault tolerance. The attack is therefore viable only in configurations with polynomial degree $t > n/2$, where the required coalition drops to half the parties or fewer._

**How to Avoid.** The following two mitigations exist:

- **Commit-before-reveal**: each party first broadcasts a commitment to its
  round-1 package, and only reveals the package after every other party's commitment
  has been seen. The attacker cannot choose its $A_{m,0}$ as a function of the
  others because the commitment binds it before any other party has opened.

- **Proof of Knowledge**: each round-1 package includes a Schnorr proof of knowledge
  of $a_{i,0}$, binding the commitment to the sender's identity and the current
  session. An attacker that chose $A_{m,0}$ adversarially cannot produce a valid
  proof without knowing the discrete log.