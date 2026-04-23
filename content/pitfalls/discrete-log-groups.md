---
title: "Discrete Log Groups"
class: "Discrete-Log Groups"
order: 10
---

The Discrete Logarithm Problem underpins several sub-protocols in MPC: Paillier-based
range proofs, DLN proofs, and Pedersen commitments all operate over a multiplicative
group $\mathbb{Z}_p^*$ (or the quadratic-residue subgroup of $\mathbb{Z}_N^*$ for the
Pedersen bases in tss-lib), where recovering $x$ from $g^x$ is assumed hard. Three
implementation failures break that assumption: using a non-safe-prime modulus, accepting
adversary-supplied group elements without checking subgroup membership, and accepting
group generators without validating they actually generate the intended subgroup.

### Non-safe-prime modulus

**What can go wrong.** When a protocol group is built over $\mathbb{Z}_p^*$ (or over
$\text{QR}_N$ for some RSA modulus $N = P \cdot Q$), DLP hardness relies on the
order of the group having only large prime factors. If $p - 1 = 2 q_1 q_2 \cdots q_k$
factors into small primes $q_i$, Pohlig–Hellman solves the discrete log in time
$O\bigl(\sum_i (\log p + \sqrt{q_i})\bigr)$ — far below the 2048-bit symmetric-level
security the modulus length suggests. The same concern applies to $\text{QR}_N$ when
$N$'s factors $P, Q$ are not safe primes: the quadratic-residue subgroup then has
smooth order.

**Security implication.** A 2048-bit modulus whose largest prime factor of $p-1$ (or of
$\phi(N)/4$) is 256 bits offers no more DLP security than a 256-bit safe-prime group.
For tss-lib's Pedersen bases $h_1, h_2 \in \text{QR}_{\tilde N}$, an adversary who
factors $\tilde N$ solves $\log_{h_1}(h_2)$ via Pohlig–Hellman and extracts the DLN
proof's witness without performing honest keygen — undermining the zero-knowledge
property of every range proof built on those bases.

**How to avoid.** Use safe primes. For DLP-based sub-protocols in MPC, generate $p$
with a safe-prime loop (both $p$ and $(p-1)/2$ are prime). For RSA-style moduli used
as DL group supports, generate both factors as safe primes and store the Sophie
Germain primes so downstream code can verify them. For standardised groups, prefer
RFC 3526 / RFC 7919 groups whose safe-prime structure is publicly audited.

**Example: tss-lib `NTilde` from RSA primes (Issue #67 / KS-BTL-F-03).** tss-lib's
keygen used Go's `rsa.GenerateMultiPrimeKey` to produce the factors of $\tilde N$.
That function generates ordinary RSA primes, not safe primes. The helper
`GetRandomGeneratorOfTheQuadraticResidue` assumed safe-prime inputs and the source
carried the comment *"THIS METHOD ONLY WORKS IF N IS THE PRODUCT OF TWO SAFE PRIMES!"*
([source](https://github.com/bnb-chain/tss-lib/issues/67)):

```go
// ecdsa/keygen/prepare.go — bnb-chain/tss-lib (vulnerable, pre-fix)
func GetRandomGeneratorOfTheQuadraticResidue(n *big.Int) *big.Int {
    r := GetRandomPositiveRelativelyPrimeInt(n)
    return new(big.Int).Mod(new(big.Int).Mul(r, r), n)
    // returns r² mod n — in QR subgroup IFF n = P*Q (safe primes)
    // with non-safe primes, QR subgroup has smooth order → DLP tractable
}
```

The fix ([commit `769ccf744f`](https://github.com/bnb-chain/tss-lib/commit/769ccf744f))
replaced RSA prime generation with an explicit safe-prime loop and stores the Sophie
Germain primes so downstream code can derive bases consistently:

```go
// ecdsa/keygen/prepare.go — bnb-chain/tss-lib (fixed)
P, Q := sgps[0].SafePrime(), sgps[1].SafePrime()
NTildei := new(big.Int).Mul(P, Q)

p, q := sgps[0].Prime(), sgps[1].Prime() // p=(P-1)/2, q=(Q-1)/2 (Sophie Germain)
f1 := common.GetRandomPositiveRelativelyPrimeInt(NTildei)
alpha := common.GetRandomPositiveRelativelyPrimeInt(NTildei)
h1i := new(big.Int).Mod(new(big.Int).Mul(f1, f1), NTildei) // h1 = f1² mod NTilde
h2i := new(big.Int).Exp(h1i, alpha, NTildei)                // h2 = h1^alpha mod NTilde
```

### Adversary-supplied group element not validated for subgroup membership

**What can go wrong.** A protocol that receives a group element from another party
must verify the element actually lies in the intended subgroup before using it in any
exponentiation with a secret exponent. The minimal check is $x^q \equiv 1 \pmod{p}$
for a $q$-order subgroup of $\mathbb{Z}_p^*$ (or the analogue in $\text{QR}_N$ for
RSA-style groups). Without it, a malicious party can submit a small-order element —
e.g., $x = p-1$, which has order 2 — and every exponentiation by an honest secret leaks
the low bits of that secret.

**Security implication.** An adversary sends $h_1 = \tilde N - 1$ (order 2 in
$\mathbb{Z}_{\tilde N}^*$). Every exponentiation $h_1^x \bmod \tilde N$ is $1$ for even
$x$, $\tilde N - 1$ for odd $x$, leaking $x \bmod 2$. Submitting a sequence of
small-order elements (order 2, 4, 8, …) drives a Pohlig–Hellman decomposition that
recovers the full secret exponent in $O(\log x)$ protocol executions. A separate
degenerate attack sends $h_1 = 1$, making every subsequent proof trivially verifiable
for any claimed discrete log.

**How to avoid.** Before using any externally-supplied base element, verify it lies in
the intended subgroup: compute $h^q \bmod N$ (or the analogous exponent for
$\mathbb{Z}_p^*$) and reject if the result is not $1$. Bounds-only checks
($h > 1$, $h < N$) catch the most degenerate values but are strictly weaker: a generic
small-order element can pass bounds and still be outside the subgroup. When the
received element is expected to share a discrete-log relationship with another base
(e.g., tss-lib's $h_1$ and $h_2$), accompany it with a DLN proof that the sender knows
$\log_{h_1}(h_2)$.

**Example: tss-lib DLN bases $h_1$, $h_2$ without bounds check (TOB-BIN-8).** The DLN
proof asserts $h_2 = h_1^x \bmod \tilde N$ for some secret $x$, proving that $h_1$ and
$h_2$ are generators of the same cyclic subgroup. Pre-fix, `Verify` accepted any
$h_1$, $h_2$ values — including $0$, $1$, $\tilde N - 1$ — without checking they lay in
$(1, \tilde N)$ or that they were distinct. The original keygen broadcast went even
further: it shipped $\tilde N, h_1, h_2$ with no DLN proof at all, so any party could
submit $h_1 = h_2$ (implicit discrete log $x = 1$) and range proofs would simply lose
their binding
([source](https://github.com/bnb-chain/tss-lib/blob/master/crypto/dlnproof/proof.go)):

```go
// crypto/dlnproof/proof.go — bnb-chain/tss-lib (pre-TOB-BIN-8, vulnerable)
func (p *Proof) Verify(h1, h2, N *big.Int) bool {
    if p == nil {
        return false
    }
    modN := common.ModInt(N)
    msg := append([]*big.Int{h1, h2, N}, p.Alpha[:]...)
    c := common.SHA512_256i(msg...)
    // ... proof equation checks ...
    // MISSING: no validation that h1, h2 ∈ (1, N) or that h1 ≠ h2
    // MISSING: no subgroup-membership check h^q ≡ 1 mod N
    return true
}
```

The TOB-BIN-8 fix ([commit `c0a1d4e4a1`](https://github.com/bnb-chain/tss-lib/commit/c0a1d4e4a1))
added element-level range checks, and the earlier keygen fix
([commit `769ccf744f`](https://github.com/bnb-chain/tss-lib/commit/769ccf744f)) added
the DLN proofs and the `h1 ≠ h2` check to the keygen round:

```go
// crypto/dlnproof/proof.go — bnb-chain/tss-lib (fixed, TOB-BIN-8)
var one = big.NewInt(1)

func (p *Proof) Verify(h1, h2, N *big.Int) bool {
    if p == nil || N.Sign() != 1 {
        return false
    }
    h1_ := new(big.Int).Mod(h1, N)
    if h1_.Cmp(one) != 1 { return false }   // h1 must be > 1
    h2_ := new(big.Int).Mod(h2, N)
    if h2_.Cmp(one) != 1 { return false }   // h2 must be > 1
    if h1_.Cmp(h2_) == 0 { return false }   // h1 ≠ h2
    for i := range p.T {
        if new(big.Int).Mod(p.T[i], N).Cmp(one) != 1 { return false }
    }
    for i := range p.Alpha {
        if new(big.Int).Mod(p.Alpha[i], N).Cmp(one) != 1 { return false }
    }
    // ... proof equation checks follow ...
}
```

TOB-BIN-8's bounds checks reject the degenerate cases ($0$, $1$, $h_1 = h_2$) but do
not themselves enforce subgroup membership — a full $h^q \equiv 1$ check is the
pre-Sinsoillier-stated minimum for adversary-supplied elements, and the accompanying
DLN proofs serve that role by proving $h_1$ and $h_2$ generate the same subgroup.

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
search on each bit. The same LSB-leak bites any protocol that uses the full group
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
### Commit Timeline

| Date | Repository | Artifact | Description |
|------|-----------|----------|-------------|
| 2016 | Van Oorschot & Wiener | [eprint 2016/995](https://eprint.iacr.org/2016/995.pdf) | LSB-leakage via non-subgroup elements; quadratic-residue generator requirement |
| 2018 | [bnb-chain/tss-lib](https://github.com/bnb-chain/tss-lib) | Initial release | NTilde uses `rsa.GenerateMultiPrimeKey` (not safe primes); no DLN proofs in keygen messages; DLN proof verifier accepts h1, h2 without range or subgroup checks |
| ~2019 | [bnb-chain/tss-lib](https://github.com/bnb-chain/tss-lib) | [Issue #67](https://github.com/bnb-chain/tss-lib/issues/67) | KS-BTL-F-03: `GetRandomGeneratorOfTheQuadraticResidue` requires safe-prime inputs |
| ~2019 | [bnb-chain/tss-lib](https://github.com/bnb-chain/tss-lib) | [commit `769ccf744f`](https://github.com/bnb-chain/tss-lib/commit/769ccf744f) | Fix: safe-prime generation for NTilde; DLN proofs added to KGRound1Message |
| ~2019 | [bnb-chain/tss-lib](https://github.com/bnb-chain/tss-lib) | [commit `c0a1d4e4a1`](https://github.com/bnb-chain/tss-lib/commit/c0a1d4e4a1) | Fix TOB-BIN-8: bounds checks on h1, h2, Alpha, T in DLN `Verify` |
| 2020 | Aumasson & Shlomovits | [eprint 2020/1052](https://eprint.iacr.org/2020/1052.pdf) | DLN proof manipulation documented as threshold-wallet attack vector |
| Jul 2023 | Verichains | [TSSHOCK](https://blog.verichains.io/p/tsshock-critical-vulnerabilities) | DLN iteration count 1 in Multichain fastMPC; c-guess requires single signing ceremony |

### Real-World Impact

**Multichain TSSHOCK (\$130M+, July 2023).** Multichain's fastMPC combined missing bounds checks on $h_1$/$h_2$, non-safe-prime DLN bases, missing session IDs, and DLN iteration count = 1. Verichains' c-guess attack extracted a signing key in a single ceremony, enabling the \$130M+ bridge drain. The DLN proof group structure ($\mathbb{Z}_{\tilde{N}}^*$ over a safe-prime product) is load-bearing for soundness: any deviation from safe-prime generation or the bounds checks on proof elements directly enables key extraction.
-->
