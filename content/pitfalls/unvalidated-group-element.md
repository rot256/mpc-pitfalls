---
title: "Group Elements Not Validated in Discrete-Log Groups"
class: input-validation
hidden: false
source: "discrete-log-groups.md"
primitives: [group, zkp, paillier, homomorphic-encryption, commitment]
---

### Group Elements Not Validated in Discrete-Log Groups

**What can go wrong.** In MPC protocols that rely on discrete-log groups (e.g.,
Pedersen-VSS over safe-prime $\mathbb{Z}_p^*$, or GG18/GG20 range-proof bases
in $\mathbb{Z}_{\tilde N}^*$), parties exchange elements that under exponentiation
with a secret exponent may leak parts of the secret if the element does not lie
in the intended subgroup. The intended
subgroup is almost always a large prime-order subgroup of $\mathbb{Z}_p^*$ (with
$p = 2q + 1$ a safe prime) or of $\mathbb{Z}_{\tilde N}^*$ (an RSA-style modulus). Three checks apply to every exchanged group element:

1. **Generator validation in safe-prime groups.** A valid generator of the $q$-order
   subgroup of $\mathbb{Z}_p^*$ must satisfy $g \equiv \pm 1 \pmod{p}$, and
   $g^{(p-1)/2} \equiv 1 \pmod{p}$. The first two exclude the trivial subgroup and
   the order-2 subgroup; the third confirms membership in the quadratic-residue
   subgroup. A generator $g = p - 1$ has order 2, so $g^x \bmod p$ is $1$ for even
   $x$ and $p - 1$ for odd $x$, leaking the LSB of the exponent on every use.
2. **Subgroup membership for received bases.** For any externally-supplied base $h$
   used as an exponentiation base, the minimal check is $h^q \equiv 1$ modulo the
   relevant modulus, for the intended subgroup order $q$: $h^q \equiv 1 \pmod{p}$
   in safe-prime groups, or $h^q \equiv 1 \pmod{\tilde N}$ in RSA-style groups, plus
   bounds $1 < h < (\text{modulus}) - 1$ to rule out the trivial cases. Bounds-only
   checks catch the most degenerate values but are strictly weaker: a generic
   small-order element can pass bounds and still be outside the subgroup.
3. **Paired bases of equal subgroup order.** When two bases $h_1, h_2$ are used
   together (as in GG18/GG20 Pedersen-style commitments $h_1^x h_2^r$), it is not
   enough to know each lies in the intended subgroup individually. Both must
   generate the *same* subgroup. The standard tool is a **DLN proof** that the
   sender knows $\alpha$ with $h_2 = h_1^{\alpha} \bmod \tilde N$, together with
   the companion proof in the reverse direction ($h_1 = h_2^{\beta} \bmod \tilde N$).

Depending on the protocol, omitting any one of them lets a amlicious party choose an element $h_a$ that leaks partial or full bits of a secret exponent on every exponentiation. See [Valenta et al., eprint 2016/995](https://eprint.iacr.org/2016/995.pdf) for the canonical analysis.

<!--All three failures collapse to the same primitive: the
adversary chooses an element of small order $n'$, and every honest exponentiation
$h^x$ leaks $x \bmod n'$. Submitting a sequence of small-order elements (order 2,
4, 8, ...) drives a Pohlig-Hellman decomposition that recovers the full secret
exponent in $O(\log x)$ protocol executions.-->
**Security implication.** Concretely in GG18 MtA, an adversary sets
$h_1 = \tilde N - 1$ (order 2 in $\mathbb{Z}_{\tilde N}^*$) so each range-proof
commitment $h_1^x h_2^r = (-1)^x h_2^r$ leaks the parity of the victim's key
share per ciphertext. When $\tilde N$ is generated without enforcing safe primes
(the pre-fix tss-lib case, see [non-safe-prime modulus](non-safe-prime-modulus.md)),
$\phi(\tilde N)$ has many small factors, additional bases of small order
$4, 8, \ldots$ exist, and combining queries via Pohlig-Hellman and CRT
reconstructs the full share in $O(\log x)$ queries. A degenerate variant ships
$\tilde N = h_1 = h_2 = 1$, making every range proof trivially verifiable so the
adversary can claim any witness.

The corresponding attack in safe-prime $\mathbb{Z}_p^*$ ([Valenta et al.](https://eprint.iacr.org/2016/995.pdf))
leaks the LSB of the secret exponent on every query that uses the full group
rather than the $q$-order subgroup. Because the only small-order element of a
true safe-prime group is $-1$, recovering more than one bit requires either the
smooth-$\phi$ cousin above, key reuse across protocols, or adaptive
bit-extraction oracles.

**How to avoid.** Validate every exchanged group element before any exponentiation
by a secret touches it. For each element supplied by another party:

- **Candidate generator in safe-prime $\mathbb{Z}_p^*$**: reject if $g \in \{1, p-1\}$, then check $g^{(p-1)/2} \equiv 1 \pmod{p}$ to confirm membership in the $q$-order subgroup.
- **Received base $h$ in $\mathbb{Z}_p^*$ or $\mathbb{Z}_{\tilde N}^*$**: reject if $h \le 1$ or $h \ge (\text{modulus}) - 1$, then check $h^q \equiv 1$ modulo the relevant modulus. Bounds alone are not enough, a generic small-order element can pass them and still leak.
- **Paired bases $h_1, h_2$ in $\mathbb{Z}_{\tilde N}^*$** (the unknown-order case): require the sender to attach a DLN proof of knowledge of $\alpha$ with $h_2 = h_1^{\alpha} \bmod \tilde N$ together with the reverse-direction proof, and reject if $h_1 = h_2$. Soundness of both DLN proofs forces $\langle h_1 \rangle = \langle h_2 \rangle$; the bounds check $h_i \notin \{1, \tilde N - 1\}$ rules out the trivial subgroups, and the safe-prime structure of $\tilde N$ (see [non-safe-prime modulus](non-safe-prime-modulus.md)) is what makes the resulting subgroup large.

As an alternative to the safe-prime generator check, **cofactor exponentiation**
([RFC 2785, §3.4](https://www.rfc-editor.org/rfc/rfc2785#section-3.4)) raises
every received element to the cofactor $j = (p-1)/q$ before use, confining all
subsequent operations to the prime-order subgroup. In a safe prime $p = 2q + 1$
the cofactor is $2$, so this reduces to squaring every input ($g' = g^2$) and
avoids the LSB leak even without an explicit generator check.

<!--For the complementary concern that
the factors of $\tilde N$ themselves must be safe primes, otherwise even a sound
DLN proof can be forged once the factorisation is smooth, see the
[non-safe-prime modulus](non-safe-prime-modulus.md) pitfall.-->
