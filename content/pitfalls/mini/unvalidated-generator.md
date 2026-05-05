---
title: "Group generator not validated"
class: "Others"
source: "discrete-log-groups.md"
---

### Group generator not validated

<div class="pitfall-flags"><span class="flag flag-tbd">TBD example</span><span class="flag flag-related">Closely related to <a href="#subgroup-generator-check-missing">Subgroup-generator check missing</a></span></div>

**What can go wrong.** For a safe-prime group $\mathbb{Z}_p^*$ with $p = 2q + 1$, a
valid generator of the $q$-order subgroup must satisfy $g \ne 1$, $g \ne p-1$, and
$g^{(p-1)/2} \equiv 1 \pmod{p}$. The first two exclude the trivial subgroup and the
order-2 subgroup; the third confirms $g$ lies in the quadratic-residue subgroup. A
generator $g = p - 1$ fails the first two checks: $g^x \bmod p$ is $1$ for even $x$ and
$p - 1$ for odd $x$, leaking the least significant bit of the exponent on every use.

**Security implication.** An attacker who observes a party's public key $g^x$ with
$g = p - 1$ immediately learns $x \bmod 2$. With access to a signing or commitment
oracle, the attacker extracts the full discrete log in $O(\log x)$ queries via binary
search on each bit. The same LSB-leak bits any protocol that uses the full group
$\mathbb{Z}_p^*$ rather than the $q$-order subgroup without the three checks above —
see [Van Oorschot & Wiener, eprint 2016/995](https://eprint.iacr.org/2016/995.pdf)
for the detailed analysis and the "square-everything" alternative that avoids the
subgroup check.

**How to avoid.** Validate every group generator before accepting it — whether it
arrives from a remote party or from a configuration file. A single helper is enough:

```go
// Validate generator g for a safe-prime group with |subgroup| = (p-1)/2
func validateGenerator(g, p *big.Int) error {
    one := big.NewInt(1)
    pMinus1 := new(big.Int).Sub(p, one)
    if g.Cmp(one) == 0 || g.Cmp(pMinus1) == 0 {
        return errors.New("generator is trivial (±1 mod p)")
    }
    q := new(big.Int).Rsh(pMinus1, 1)
    if new(big.Int).Exp(g, q, p).Cmp(one) != 0 {
        return errors.New("g does not generate the q-order subgroup")
    }
    return nil
}
```

The alternative (per eprint 2016/995) is to restrict every exponent-using operation to
the quadratic-residue subgroup by squaring all inputs ($g' = g^2$), which avoids the
LSB leak even without an explicit generator check.

**Example.** *TBD.* The LSB-leak attack is documented in
[eprint 2016/995](https://eprint.iacr.org/2016/995.pdf) but no specific MPC-library CVE
is pinned to it on this page yet.

<!--
