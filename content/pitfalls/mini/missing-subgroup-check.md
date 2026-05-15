---
title: "Adversary-Supplied Group Element Not Validated for Subgroup Membership"
class: others
source: "discrete-log-groups.md"
primitives: [group, zkp]
---

### Adversary-Supplied Group Element Not Validated for Subgroup Membership

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
