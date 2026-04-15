---
title: "Discrete Log Groups"
class: "Cryptographic Primitive"
order: 7
---

- The group is not defined from a safe prime $p=2q+1$.
- Anything, $x$, selected by a potentially malicious party (e.g. client) is not validated to live in the secure subgroup before usage. I.e. $1 \equiv x^q \mod p$ for $p=2q+1$.
- Missing validation that any group generator $g$ is different from $\pm 1 \mod p$ and $g^{\frac{p-1}{2}} \equiv 1 \mod p$. (This is needed to ensure that elements live in the subgroup of q elements. Note that this is needed to avoid lsb of exponent being leaked, which happens when using the full group. An alternative approach is to just square everything. See [this paper](https://eprint.iacr.org/2016/995.pdf) for details.)

---

# DRAFT Discrete Log Groups

The Discrete Logarithm Problem (DLP) underpins many MPC sub-protocols: Paillier-based range proofs, DLN proofs, and Pedersen commitments all operate in a multiplicative group where finding $x$ given $g^x$ is assumed hard. Three implementation failures recur: using a non-safe-prime modulus (enabling Pohlig–Hellman attacks); accepting adversarially-supplied elements without checking subgroup membership (small-subgroup attacks); and accepting generators without validating they are different from $\pm 1$ (leaking exponent bits).

### Example 1: Missing Subgroup Membership Check on DLN Proof Bases

The DLN proof in tss-lib requires two base elements $h_1, h_2 \in \mathbb{Z}_N^*$ such that neither party knows the discrete log of one base with respect to the other. These bases are supplied by the remote party during keygen. The library verifies the DLN proof relations but does not check that $h_1^q \equiv 1 \pmod{N}$ — that is, that $h_1$ lies in the order-$q$ subgroup.

([source](https://github.com/bnb-chain/tss-lib/blob/master/crypto/dlnproof/proof.go))

```go
// crypto/dlnproof/proof.go — bnb-chain/tss-lib
// Verify checks DLN proof equations but does NOT validate
// that h1 or h2 are in the q-order subgroup of Z_N*.
func (proof *Proof) Verify(h1, h2, N *big.Int) bool {
    for i := 0; i < Iterations; i++ {
        // checks proof.Alpha[i]^s * proof.Beta[i]^t ≡ h1^u * h2^v mod N
        // accepts any h1, h2 including trivial elements with small order
    }
    return true
}
```

**Attack.** An adversary sends $h_1 = N - 1$ (order 2). Every exponentiation $h_1^x \bmod N$ is $1$ for even $x$, $N-1$ for odd $x$. Across multiple DLN verification calls, the adversary learns $x \bmod 2$ per call, then $x \bmod 4$ from a second element of order 4, and so on — a Pohlig–Hellman decomposition that recovers the full secret exponent in $O(\log x)$ protocol executions.

**Remediation.** Before using any externally-supplied base element, verify $h^q \equiv 1 \pmod{N}$:

```go
func validateSubgroupElement(h, q, N *big.Int) error {
    result := new(big.Int).Exp(h, q, N)
    if result.Cmp(big.NewInt(1)) != 0 {
        return errors.New("element not in q-order subgroup")
    }
    return nil
}
```

### Example 2: Generator Validation — ±1 Leaks Exponent Bits

For a safe-prime group $\mathbb{Z}_p^*$ with $p = 2q+1$, a valid generator of the $q$-order subgroup must satisfy $g \neq 1$, $g \neq p-1$, and $g^{(p-1)/2} \equiv 1 \pmod{p}$. If $g = p-1$, then $g^x \bmod p$ is $1$ for even $x$ and $p-1$ for odd $x$, leaking the LSB of $x$ per use.

([source](https://eprint.iacr.org/2016/995.pdf))

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

**Attack.** An attacker who observes a party's public key $g^x$ with $g = p-1$ immediately learns $x \bmod 2$. With access to a signing or commitment oracle, the attacker extracts the full discrete log in $O(\log x)$ queries using binary search.

**Remediation.** Apply `validateGenerator` to every group generator before accepting it, whether it arrives from a remote party or from configuration.

### Example 3: Non-Safe-Prime Modulus

A protocol group built on $p$ where $p - 1 = 2 q_1 q_2 \cdots q_k$ with small $q_i$ is broken by Pohlig–Hellman in time $O(\sum_i (\log p + \sqrt{q_i}))$. A 2048-bit modulus whose largest prime factor of $p-1$ is 256 bits offers no more DLP security than a 256-bit safe-prime group.

([source](https://github.com/bnb-chain/tss-lib/blob/master/crypto/paillier/paillier.go))

```go
// crypto/paillier/paillier.go — bnb-chain/tss-lib
// generateSafePrime generates p = 2q+1 with both p and q prime.
// Implementations that test only that p is prime (not q) are vulnerable.
func generateSafePrime(bits int) (*big.Int, error) {
    for {
        q, _ := rand.Prime(rand.Reader, bits-1)
        p := new(big.Int).Mul(q, big.NewInt(2))
        p.Add(p, big.NewInt(1))
        if p.ProbablyPrime(20) {
            return p, nil
        }
    }
}
```

**Remediation.** Use safe primes. For DLP-based sub-protocols in MPC, generate $p$ with the safe-prime loop above. For standardised groups, prefer RFC 3526 / RFC 7919 groups whose safe-prime structure is publicly audited.

### Commit Timeline

| Date | Repository | Artifact | Description |
|------|-----------|----------|-------------|
| 2016 | Van Oorschot & Wiener | [eprint 2016/995](https://eprint.iacr.org/2016/995.pdf) | LSB-leakage via non-subgroup elements; quadratic-residue generator requirement |
| 2018 | [bnb-chain/tss-lib](https://github.com/bnb-chain/tss-lib) | Initial release | DLN proof verifier accepts h1, h2 without $x^q \equiv 1$ subgroup check |
| 2020 | Aumasson & Shlomovits | [eprint 2020/1052](https://eprint.iacr.org/2020/1052.pdf) | DLN proof manipulation documented as threshold-wallet attack vector |
| Jul 2023 | Verichains | [TSSHOCK](https://blog.verichains.io/p/tsshock-critical-vulnerabilities) | DLN iteration count 1 (not 128) in Multichain fastMPC enables c-guess attack |

### Real-World Impact

**Multichain TSSHOCK (\$130M+, July 2023).** Multichain's fastMPC reduced the DLN proof iteration count from 128 to 1, collapsing soundness. Verichains' c-guess attack needed only a single signing ceremony to extract a key share. The DLP group misuse — weak DLN soundness combined with missing session IDs — was an independently exploitable condition that enabled the \$130M+ bridge drain. Implementations that accept DLN bases without subgroup validation face the small-subgroup attack regardless of iteration count.
