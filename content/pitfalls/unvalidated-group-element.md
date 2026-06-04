---
title: "Group Elements Not Validated in Discrete-Log Groups"
class: input-validation
hidden: false
order: 2
source: "discrete-log-groups.md"
primitives: [group, zkp, paillier, homomorphic-encryption, commitment]
bugs: [tss-lib-dln-bases]
display: [tss-lib-dln-bases]
---


**What can go wrong.** In MPC protocols that rely on discrete-log groups (e.g., Pedersen-VSS over safe-prime $\mathbb{Z}_p^*$, or GG18/GG20 range-proof bases in $\mathbb{Z}_{\tilde N}^*$), parties exchange elements that under exponentiation with a secret exponent may leak part or all of the secret if the element does not lie in the intended subgroup. The intended subgroup is almost always a large prime-order subgroup of $\mathbb{Z}_p^*$ (with $p = 2q + 1$ a safe prime) or of $\mathbb{Z}_{\tilde N}^*$ (an RSA-style modulus). Three checks apply to every exchanged group element:

1. **Generator validation in safe-prime groups.** A valid generator of the $q$-order subgroup of $\mathbb{Z}_p^*$ must satisfy $g \not\equiv 1 \pmod{p}$, $g \not\equiv p - 1 \pmod{p}$, and $g^{(p-1)/2} \equiv 1 \pmod{p}$. The first two exclude the trivial subgroup and the order-2 subgroup; the third confirms membership in the quadratic-residue subgroup.
2. **Subgroup membership for received bases.** For any supplied exponentiation base $x$, you must make sure $x$ lives in the intended secure subgroup by checking $x^q \equiv 1 \pmod{p}$ for a safe-prime $p$, and also check the bounds $1 < x < p - 1$ to rule out the trivial cases. Bounds-only checks catch the most degenerate values, but a generic small-order element can pass bounds and still be outside the subgroup.

3. **Paired bases of equal subgroup order.** When two bases $h_1, h_2$ are used together (as in GG18/GG20 Pedersen-style commitments $h_1^s h_2^r$), it is not enough to know each lies in the intended subgroup individually. Both must generate the *same* subgroup. The standard tool is a **DLN proof** that the sender knows $\alpha$ with $h_2 = h_1^{\alpha} \bmod \tilde N$, together with the companion proof in the reverse direction ($h_1 = h_2^{\beta} \bmod \tilde N$).

Depending on the protocol, omitting any one of these checks lets a malicious party choose an element $x$ that leaks partial or full bits of a secret exponent on every exponentiation.


**Security implication.** Concretely in GG18 MtA, as [analyzed by Hexens](https://hexens.io/blog/mpc-attacks-p1), an adversary can set $h_2 = 1$ so $z = h_1^s \bmod \tilde N$ leaks $h_1^s$. When $\tilde N$ is generated without enforcing safe primes (see [non-safe-prime modulus](#non-safe-prime-modulus)), the attacker can choose $\tilde N$ as a product of small prime factors so that $\phi(\tilde N)$ is smooth, and combining Pohlig-Hellman on each factor with CRT reconstructs the full share. Alternatively, an attacker can choose $\tilde N$ large enough that recovering $s$ reduces to computing integer logarithms, which is trivial with standard algorithms.

**How to avoid.** Validate every exchanged group element before any exponentiation
by a secret touches it. For each element supplied by another party:

- **Candidate generator in safe-prime $\mathbb{Z}_p^*$**: reject if $g \in \{1, p-1\}$, then check $g^{(p-1)/2} \equiv 1 \pmod{p}$ to confirm membership in the $q$-order subgroup.
- **Received base $x$ in $\mathbb{Z}_p^*$**: for a safe-prime $p=2q + 1$, before any use of $x$, check $1 < x < p - 1$, and check $x^q \equiv 1 \pmod{p}$.
- **Paired bases $h_1, h_2$ in $\mathbb{Z}_{\tilde N}^*$** (the unknown-order case): reject if $h_i \in \{1, \tilde N - 1\}$ or $h_1 = h_2$; require the sender to attach a DLN proof of knowledge of $\alpha$ with $h_2 = h_1^{\alpha} \bmod \tilde N$ together with the reverse-direction proof; and require a structural proof on $\tilde N$ itself (biprimality with safe-prime factors of standard size, see [non-safe-prime modulus](#non-safe-prime-modulus)), with a bound on $|\tilde N|$ to rule out adversarially oversized moduli. Soundness of both DLN proofs forces $\langle h_1 \rangle = \langle h_2 \rangle$; the structural proof and size bound prevent the smooth-$\phi$ and integer-log attacks respectively.

As an alternative to the bullets above for safe-prime $\mathbb{Z}_p^*$, **cofactor exponentiation**
([RFC 2785, §3.4](https://www.rfc-editor.org/rfc/rfc2785#section-3.4)) raises
every received element to the cofactor $j = (p-1)/q$ before use, confining all
subsequent operations to the prime-order subgroup. In a safe prime $p = 2q + 1$
the cofactor is $2$, so this reduces to squaring every input ($g' = g^2$) and
confines exponentiations to the prime-order subgroup without an explicit generator check.