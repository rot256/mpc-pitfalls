---
title: "Rogue-Key Attack: No Commit-Before-Reveal and No Proof of Knowledge"
class: "Adaptive Inputs"
source: "feldman-vss.md"
---

### Rogue-Key Attack: No Commit-Before-Reveal and No Proof of Knowledge

**What can go wrong.** A *distributed key generation* (DKG) protocol lets $n$ parties jointly produce a public key whose corresponding secret is shared among them, with no trusted dealer. In a Feldman-based DKG (the joint-Feldman construction of [Pedersen, 1991](https://link.springer.com/chapter/10.1007/3-540-46416-6_47); the underlying VSS primitive is from [Feldman, 1987](https://ieeexplore.ieee.org/document/4568297/)), each party $P_i$ broadcasts $A_{i,0} = g^{a_{i,0}}$, which is a commitment to its secret contribution $a_{i,0}$.  A shared public key is then defined as $Y = \prod_i A_{i,0}$. If the protocol neither requires parties to commit to their first-round messages before seeing others' contributions nor requires each party to prove knowledge of $a_{i,0}$, a malicious party or coalition may wait to see the honest parties' commitments and then choose its public contribution as a function of theirs. 

Note that at the aggregate-key level, this lets the attacker try to force the shared public key to be a key it controls. In a full Joint-Feldman DKG, the malicious contribution must also pass share verification, which is why the concrete Drand attack below requires a coalition in the relevant threshold regime.

**Security implication.** Let $Y^\star = g^x$ be the adversary's target (a key for
which it holds the discrete log $x$). After observing
$A_{1,0}, \dots, A_{n-1,0}$, $P_m$ announces $A_{m,0} = Y^\star \cdot
\left(\prod_{i \ne m} A_{i,0}\right)^{-1}$. Multiplying all commitments yields
$\prod_i A_{i,0} = Y^\star$. The shared "threshold" key is now under $P_m$'s sole
control. As a consequence, reconstruction is not required and the protocol's threshold property no longer holds.

**How to avoid.** Either of the following two mitigations is sufficient; most
deployments use both:

- **Commit-before-reveal**: each party first broadcasts a commitment to its
  round-1 package, and only reveals the package after every other party's commitment
  has been seen. The attacker cannot choose its $A_{m,0}$ as a function of the
  others because the commitment binds it before any other party has opened.

- **Proof of knowledge**: each round-1 package includes a Schnorr proof of knowledge
  of $a_{i,0}$, binding the commitment to the sender's identity and the current
  session. An attacker that chose $A_{m,0}$ adversarially cannot produce a valid
  proof without knowing the discrete log.

**Example 1: Drand DKG threshold constraint ([Sigma Prime, 2020](https://blog.sigmaprime.io/dkg-rogue-key.html)).**
Drand's [protocol specification](https://docs.drand.love/docs/specification) describes
it as a distributed randomness beacon using DKG and threshold BLS, with a threshold above
half the participants under its security model. Sigma Prime showed that
when the polynomial degree $t$ exceeds $n/2$ (that is, a $(t+1)$-of-$n$ reconstruction
threshold), a coalition of $m \ge n - t + 1$ parties can mount a rogue-key attack: after
seeing the honest parties' public commitments, the colluding parties choose their own
constant-term commitments so the final public key becomes an attacker-chosen
$Y^\star = g^x$. The attacker then knows the discrete log of the group public key.

The post proposes an initial hash commit-before-reveal phase over each party's polynomial
commitments, for example `Hash(A_{i,0} || A_{i,1} || ... || A_{i,t})`, before any
commitment values are revealed. Drand instead lowered the configured threshold closer to
$n/2$, so the rogue-key attack would require a coalition outside the assumed fault bound.

**Example 2: Reference correct shape in FROST ([Komlo–Goldberg, 2020](https://eprint.iacr.org/2020/852)).** The FROST DKG explicitly includes a Schnorr proof of knowledge in round 1 as a documented rogue-key mitigation. Zcash Foundation's implementation pins $a_{i,0}$ to the sender's identity through a `proof_of_knowledge` field on the round-1 package ([source](https://github.com/ZcashFoundation/frost/blob/main/frost-core/src/keys/dkg.rs)):

```rust
// frost-core/src/keys/dkg.rs — Zcash Foundation FROST
pub struct Package<C: Ciphersuite> {
    pub commitment: VerifiableSecretSharingCommitment<C>,
    pub proof_of_knowledge: Signature<C>, // Schnorr PoK of a_{i,0}
}

pub fn part1<C: Ciphersuite>(...) -> Result<(SecretPackage<C>, Package<C>)> {
    let proof_of_knowledge = compute_proof_of_knowledge(&coefficients[0], identifier, ...);
    Ok((secret_package, Package { commitment, proof_of_knowledge }))
}
```

An adversary who chose $A_{m,0}$ as a function of other parties' commitments cannot produce a valid Schnorr signature without knowing the discrete log of its own first coefficient commitment, so the rogue-key strategy is detected at round-1 verification. 
