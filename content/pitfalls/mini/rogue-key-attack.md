---
title: "Rogue-key attack: no commit-before-reveal and no proof of knowledge"
class: "Multi-Party Accountability"
source: "feldman-vss.md"
---

### Rogue-key attack: no commit-before-reveal and no proof of knowledge

**What can go wrong.** In a Feldman-based DKG, each party $P_i$ broadcasts
$A_{i,0} = g^{a_{i,0}}$ — the commitment to its secret contribution $a_{i,0}$ — and
the shared public key is $Y = \prod_i A_{i,0}$. If the protocol neither requires
parties to commit to their first-round messages before seeing others' contributions
nor requires each party to prove knowledge of $a_{i,0}$, a malicious party waits to
see all other parties' commitments and then chooses its own $A_{m,0}$ as a function
of theirs. The attacker can thereby force the shared public key to be a key it alone
controls.

**Security implication.** Let $Y^\star = g^x$ be the adversary's target (a key for
which it holds the discrete log $x$). After observing
$A_{1,0}, \dots, A_{n-1,0}$, $P_m$ announces $A_{m,0} = Y^\star \cdot
\left(\prod_{i \ne m} A_{i,0}\right)^{-1}$. Multiplying all commitments yields
$\prod_i A_{i,0} = Y^\star$. The shared "threshold" key is now under $P_m$'s sole
control — reconstruction is not required and the $(t, n)$ threshold property is
vacuous.

**How to avoid.** Either of the following two mitigations is sufficient; most
deployments use both:

- **Commit-before-reveal**: each party first broadcasts a hash commitment to its
  round-1 package, and only reveals the package after every other party's commitment
  has been seen. The attacker cannot choose its $A_{m,0}$ as a function of the
  others because the hash binds it before any other party has opened.
- **Proof of knowledge**: each round-1 package includes a Schnorr proof of knowledge
  of $a_{i,0}$, binding the commitment to the sender's identity and the current
  session. An attacker that chose $A_{m,0}$ adversarially cannot produce a valid
  proof without knowing the discrete log.

**Example: synthetic round-1 package without PoK, FROST reference.** The vulnerable
shape is a commitment broadcast with no accompanying proof:

```go
// INSECURE DKG round 1: commitment broadcast without proof of knowledge
type Round1Package struct {
    Commitment []*ECPoint // g^{a_{i,j}} for j = 0..t-1
    // MISSING: proof of knowledge of a_{i,0}
    // Adversary can wait, observe all A_{i,0}, then choose A_{m,0} to cancel them
}
```

ZCash Foundation's FROST closes this by including a `proof_of_knowledge` field that
pins down $a_{i,0}$ to the sender's identity
([source](https://github.com/ZcashFoundation/frost/blob/main/frost-core/src/keys/dkg.rs)):

```rust
// frost-core/src/keys/dkg.rs — ZCash Foundation FROST (correct approach)
pub struct Package<C: Ciphersuite> {
    pub commitment: VerifiableSecretSharingCommitment<C>,
    pub proof_of_knowledge: Signature<C>, // Schnorr PoK of a_{i,0}
}

pub fn part1<C: Ciphersuite>(...) -> Result<(SecretPackage<C>, Package<C>)> {
    let proof_of_knowledge = compute_proof_of_knowledge(&coefficients[0], identifier, ...);
    Ok((secret_package, Package { commitment, proof_of_knowledge }))
}
```

The rogue-key attack vector has been known since the early DKG literature; its
recurrence across modern implementations — Trail of Bits' 2024 disclosure found both
the length-check and rogue-key failures in multiple libraries at once — underscores
that spec-level mitigations do not reliably translate into implementation-level
checks without explicit auditing.

<!--
