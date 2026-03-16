---
title: "RSA-Style Moduli"
class: "Cryptographic Primitive"
order: 6
---

- Not validating that the private key $d>N^{\frac{1}{4}}$.
- Not validating that a base element has order 2 or 4.

#### Recommendations

When used in custom protocols it is strongly recommended to ensure the following as well:

- $p$ and $q$ are safe primes.
- $p$ and $q$ are strong primes.
- If the group is used for signatures, then PSS padding is used.
- If the group is used for encryption then OAEP is used.

### Example

In bnb-chain/tss-lib < v1.2.0 (CVE-2020-12118), keygen [round 2](https://github.com/bnb-chain/tss-lib/blob/4fcd04b0ce5527ece51afa70c7852b5fd03b120c/ecdsa/keygen/round_2.go#L22-L44) stored $h_1$, $h_2$, and $\tilde{N}$ from other parties without any discrete-log proof verification:

```go
// ecdsa/keygen/round_2.go — bnb-chain/tss-lib v1.1.1
for j, msg := range round.temp.kgRound1Messages {
    r1msg := msg.Content().(*KGRound1Message)
    round.save.PaillierPKs[j] = r1msg.UnmarshalPaillierPK()
    round.save.NTildej[j] = r1msg.UnmarshalNTilde()
    round.save.H1j[j], round.save.H2j[j] = r1msg.UnmarshalH1(), r1msg.UnmarshalH2()
    round.temp.KGCs[j] = r1msg.UnmarshalCommitment()
}
```

A malicious party could supply arbitrary $h_1$, $h_2$, $\tilde{N}$ values, compromising the zero-knowledge proofs that rely on these parameters.

- Even after the v1.2.0 fix (which added DLN proofs), the Paillier modulus $N$ itself was still accepted without a biprimality check. CVE-2023-33241 (BitForge, CVSS 9.1) exploited this: an attacker constructs $N = p_1 \cdots p_{16} \cdot q$ with small $p_i$, forges range proofs, and extracts 16 bits of the victim's key share per signing session. Five libraries were affected.

### References

- Fireblocks, [BitForge: Fireblocks Research Uncovers Vulnerabilities in Over 15 Major MPC Wallets](https://www.fireblocks.com/blog/bitforge-fireblocks-researchers-uncover-vulnerabilities-in-over-15-major-wallet-providers/), August 2023.
- [CVE-2023-33241](https://nvd.nist.gov/vuln/detail/CVE-2023-33241), [CVE-2020-12118](https://nvd.nist.gov/vuln/detail/CVE-2020-12118).
- [GHSA-399h-cmvp-qgx5](https://github.com/advisories/GHSA-399h-cmvp-qgx5).
- PoC: [fireblocks-labs/safeheron-gg20-exploit-poc](https://github.com/fireblocks-labs/safeheron-gg20-exploit-poc).
