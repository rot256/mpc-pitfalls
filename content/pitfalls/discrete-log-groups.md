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

---

# DRAFT Discrete Log Groups (Revised)

In tss-lib and GG18/GG20-based threshold protocols, discrete-log groups appear in two distinct roles: the **Pedersen commitment modulus** $\tilde{N} = P \cdot Q$ (where $P = 2p+1$, $Q = 2q+1$ are safe primes) serves as the base ring for DLN proofs and MtA range proofs; and the **Paillier modulus** $N = p_0 q_0$ serves for homomorphic encryption. Both require safe-prime factors — they operate over $\mathbb{Z}_{\tilde{N}}^*$ or $\mathbb{Z}_{N}^*$, not over a simple safe-prime field $\mathbb{Z}_p^*$. Three implementation failures weaken these groups.

### Example 1: DLN Proof Bases h1, h2 Without Bounds Check (TOB-BIN-8)

The DLN proof asserts $h_2 = h_1^x \bmod \tilde{N}$ for some secret $x$, proving that $h_1$ and $h_2$ are generators of the same cyclic subgroup of $\mathbb{Z}_{\tilde{N}}^*$. Before the Trail of Bits audit fix, the `Verify` function accepted any $h_1$, $h_2$ values — including $0$, $1$, $\tilde{N}-1$ — without checking that they lie in the valid range $(1, \tilde{N})$ or that they are distinct.

([source](https://github.com/bnb-chain/tss-lib/blob/master/crypto/dlnproof/proof.go))

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
    // MISSING: no bounds check on Alpha[i] or T[i] values
    return true
}
```

**Attack.** An adversary sends $h_1 = \tilde{N} - 1$ (order 2 in $\mathbb{Z}_{\tilde{N}}^*$). Every exponentiation $h_1^x \bmod \tilde{N}$ is $1$ for even $x$ and $\tilde{N}-1$ for odd $x$, leaking $x \bmod 2$ per DLN verification call. Submitting elements of successively higher small order enables Pohlig–Hellman decomposition of the full exponent. A separate attack sends $h_1 = 1$, making every DLN proof trivially verifiable for any claimed $x$.

**Remediation.** The TOB-BIN-8 fix ([commit `c0a1d4e4a1`](https://github.com/bnb-chain/tss-lib/commit/c0a1d4e4a1)) added range checks for every element in `Verify`:

([source](https://github.com/bnb-chain/tss-lib/commit/c0a1d4e4a1))

```go
// crypto/dlnproof/proof.go — bnb-chain/tss-lib (fixed, TOB-BIN-8)
var one = big.NewInt(1)

func (p *Proof) Verify(h1, h2, N *big.Int) bool {
    if p == nil || N.Sign() != 1 {
        return false
    }
    h1_ := new(big.Int).Mod(h1, N)
    if h1_.Cmp(one) != 1 {    // h1 must be > 1
        return false
    }
    h2_ := new(big.Int).Mod(h2, N)
    if h2_.Cmp(one) != 1 {    // h2 must be > 1
        return false
    }
    if h1_.Cmp(h2_) == 0 {    // h1 ≠ h2
        return false
    }
    for i := range p.T {
        if new(big.Int).Mod(p.T[i], N).Cmp(one) != 1 {
            return false
        }
    }
    for i := range p.Alpha {
        if new(big.Int).Mod(p.Alpha[i], N).Cmp(one) != 1 {
            return false
        }
    }
    // ... proof equation checks follow ...
}
```

### Example 2: NTilde Generated from Non-Safe Primes (Issue #67, KS-BTL-F-03)

The function `GetRandomGeneratorOfTheQuadraticResidue` requires its argument to be a product of two **safe** primes. This is necessary for the quadratic-residue subgroup to have prime order $p \cdot q$ — required for DLN proof soundness. The original keygen code generated $\tilde{N}$'s factors using `rsa.GenerateMultiPrimeKey`, which produces RSA primes, not safe primes. The source code itself contained the warning: *"THIS METHOD ONLY WORKS IF N IS THE PRODUCT OF TWO SAFE PRIMES!"*

([source](https://github.com/bnb-chain/tss-lib/issues/67))

```go
// ecdsa/keygen/prepare.go — bnb-chain/tss-lib (vulnerable, pre-fix)
func GetRandomGeneratorOfTheQuadraticResidue(n *big.Int) *big.Int {
    r := GetRandomPositiveRelativelyPrimeInt(n)
    return new(big.Int).Mod(new(big.Int).Mul(r, r), n)
    // returns r² mod n — in QR subgroup IFF n = P*Q (safe primes)
    // with non-safe primes, QR subgroup has smooth order → DLP tractable
}
```

**Attack.** With non-safe-prime $\tilde{N}$, the order of $\text{QR}_{\tilde{N}}$ has small factors. An adversary recovers the factorisation and solves $\log_{h_1}(h_2) \bmod \tilde{N}$ via Pohlig–Hellman, extracting the DLN proof witness $x$ without performing honest keygen. This undermines the zero-knowledge property of the DLN proof and the hiding property of the MtA range proofs that use $h_1$, $h_2$ as Pedersen bases.

**Remediation.** The fix ([commit `769ccf744f`](https://github.com/bnb-chain/tss-lib/commit/769ccf744f)) replaced RSA prime generation with an explicit safe-prime loop and stores the Sophie Germain primes:

([source](https://github.com/bnb-chain/tss-lib/commit/769ccf744f))

```go
// ecdsa/keygen/prepare.go — bnb-chain/tss-lib (fixed)
P, Q := sgps[0].SafePrime(), sgps[1].SafePrime()
NTildei := new(big.Int).Mul(P, Q)

p, q := sgps[0].Prime(), sgps[1].Prime() // Sophie Germain primes: p=(P-1)/2, q=(Q-1)/2
f1 := common.GetRandomPositiveRelativelyPrimeInt(NTildei)
alpha := common.GetRandomPositiveRelativelyPrimeInt(NTildei)
h1i := new(big.Int).Mod(new(big.Int).Mul(f1, f1), NTildei) // h1 = f1² mod NTilde
h2i := new(big.Int).Exp(h1i, alpha, NTildei)                // h2 = h1^alpha mod NTilde
```

### Example 3: DLN Proof Bases Not Proven Consistent in Keygen

Before commit `769ccf744f`, the `KGRound1Message` broadcast $\tilde{N}$, $h_1$, $h_2$ with **no DLN proof**. Any party could send an arbitrary $h_1$, $h_2$ pair — including degenerate or adversarially chosen pairs — with no cryptographic enforcement.

([source](https://github.com/bnb-chain/tss-lib/commit/769ccf744f))

```go
// ecdsa/keygen/messages.go — bnb-chain/tss-lib (pre-fix)
func NewKGRound1Message(
    from *tss.PartyID, ct cmt.HashCommitment,
    paillierPK *paillier.PublicKey,
    nTildeI, h1I, h2I *big.Int,
) tss.ParsedMessage {
    content := &KGRound1Message{
        NTilde: nTildeI.Bytes(),
        H1:     h1I.Bytes(),
        H2:     h2I.Bytes(),
        // No Dlnproof_1, no Dlnproof_2
    }
}
```

**Attack.** A malicious party sends $h_1 = h_2$. The implicit discrete log is $x = 1$ — trivially known. Range proofs using $h_1$, $h_2$ as Pedersen bases lose their binding property.

**Remediation.** The same commit added two DLN proofs to the keygen message and verification plus a uniqueness check in round 2:

```go
// ecdsa/keygen/round_2.go — bnb-chain/tss-lib (fixed)
if dlnProof1, err := r1msg.UnmarshalDLNProof1();
   err != nil || !dlnProof1.Verify(H1j, H2j, NTildej) {
    dlnProof1FailCulprits = append(dlnProof1FailCulprits, msg.GetFrom())
}
if dlnProof2, err := r1msg.UnmarshalDLNProof2();
   err != nil || !dlnProof2.Verify(H2j, H1j, NTildej) {
    dlnProof2FailCulprits = append(dlnProof2FailCulprits, msg.GetFrom())
}
if H1j.Cmp(H2j) == 0 {
    return round.WrapError(errors.New("h1j and h2j were equal for this party"), ...)
}
```

### Commit Timeline

| Date | Repository | Artifact | Description |
|------|-----------|----------|-------------|
| 2018 | [bnb-chain/tss-lib](https://github.com/bnb-chain/tss-lib) | Initial release | NTilde uses `rsa.GenerateMultiPrimeKey` (not safe primes); no DLN proofs in keygen messages |
| ~2019 | [bnb-chain/tss-lib](https://github.com/bnb-chain/tss-lib) | [Issue #67](https://github.com/bnb-chain/tss-lib/issues/67) | KS-BTL-F-03: `GetRandomGeneratorOfTheQuadraticResidue` requires safe-prime inputs |
| ~2019 | [bnb-chain/tss-lib](https://github.com/bnb-chain/tss-lib) | [commit `769ccf744f`](https://github.com/bnb-chain/tss-lib/commit/769ccf744f) | Fix: safe-prime generation for NTilde; DLN proofs added to KGRound1Message |
| ~2019 | [bnb-chain/tss-lib](https://github.com/bnb-chain/tss-lib) | [commit `c0a1d4e4a1`](https://github.com/bnb-chain/tss-lib/commit/c0a1d4e4a1) | Fix TOB-BIN-8: bounds checks on h1, h2, Alpha, T in DLN `Verify` |
| 2020 | Aumasson & Shlomovits | [eprint 2020/1052](https://eprint.iacr.org/2020/1052.pdf) | DLN proof manipulation documented as threshold-wallet attack vector |
| Jul 2023 | Verichains | [TSSHOCK](https://blog.verichains.io/p/tsshock-critical-vulnerabilities) | DLN iteration count 1 in Multichain fastMPC; c-guess requires single signing ceremony |

### Real-World Impact

**Multichain TSSHOCK (\$130M+, July 2023).** Multichain's fastMPC combined missing bounds checks on $h_1$/$h_2$, non-safe-prime DLN bases, missing session IDs, and DLN iteration count = 1. Verichains' c-guess attack extracted a signing key in a single ceremony, enabling the \130M+ bridge drain. The DLN proof group structure ($\mathbb{Z}_{\tilde{N}}^*$ over a safe-prime product) is load-bearing for soundness: any deviation from safe-prime generation or the bounds checks on proof elements directly enables key extraction.
