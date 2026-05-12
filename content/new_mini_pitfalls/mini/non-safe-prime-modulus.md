---
title: "Non-Safe-Prime Modulus"
class: "Others"
source: "discrete-log-groups.md"
---

### Non-Safe-Prime Modulus

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
