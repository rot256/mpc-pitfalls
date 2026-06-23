---
title: "BitGo TSS missing Paillier biprimality check"
date: 2023-08-09
primitives: [paillier, homomorphic-encryption, zkp]
repository: https://github.com/BitGo/BitGoJS
pr: [3590, 3602, 3634]
source:
  - name: "Hexens, MPC attacks (part 1)"
    url: https://hexens.io/blog/mpc-attacks-p1
  - name: "Goldberg-Reyzin RSA modulus certification"
    url: https://eprint.iacr.org/2018/057
cve:
  name: CVE-2023-33241
  url: https://nvd.nist.gov/vuln/detail/CVE-2023-33241
---

BitGo's TSS implementation in `BitGoJS` followed the GG18 key-generation
protocol but skipped the biprimality phase entirely. Incoming Paillier
moduli from co-signers were accepted with no proof that $N = pq$ for primes
$p, q$ of safe size, and no proof of knowledge of the underlying share.

Hexens demonstrated a working extraction attack using a chosen-modulus
form. The attacker publishes a malicious Paillier public key $(N, V)$
where $N$ has a small smooth factor (e.g. $N = pq$ with $q$ small enough
that discrete log in $\mathbb{Z}_q^\ast$ is tractable) and $V$ is an
arbitrary quadratic residue. When the victim encrypts their share $x$
under $N$ during signing, the attacker reduces the ciphertext modulo $q$
and computes $C^{p+1} \bmod q$ to isolate $V^x \bmod q$. Brute-force
discrete log recovers $x \bmod q$. Repeating across signing sessions and
combining residues via CRT reconstructs the full 256-bit share, after
which the attacker holds enough material to sign unilaterally under the
joint key.

The same root cause was disclosed at scale as
[BitForge](https://www.fireblocks.com/blog/bitforge-fireblocks-researchers-uncover-vulnerabilities-in-over-15-major-wallet-providers/)
(CVE-2023-33241) covering five major GG18/GG20 libraries; BitGo was the
case study in Hexens' independent
[analysis](https://hexens.io/blog/mpc-attacks-p1).

BitGo's remediation implements the Goldberg-Reyzin RSA-modulus certification
proof ([eprint 2018/057](https://eprint.iacr.org/2018/057)), not the CGGMP21
Paillier-Blum plus No-Small-Factor proof pair. The verifier landed across
[PR #3590](https://github.com/BitGo/BitGoJS/pull/3590),
[PR #3602](https://github.com/BitGo/BitGoJS/pull/3602), and
[PR #3634](https://github.com/BitGo/BitGoJS/pull/3634), which made the proof
mandatory. The implementation in
[`modules/sdk-lib-mpc/src/tss/ecdsa/paillierproof.ts`](https://github.com/BitGo/BitGoJS/blob/master/modules/sdk-lib-mpc/src/tss/ecdsa/paillierproof.ts)
rejects $N$ divisible by any prime up to $\alpha = 319567$, then verifies the
Paillier challenge-response proofs $\sigma_i^N \equiv p_i \pmod N$:

```typescript
// FILE: modules/sdk-lib-mpc/src/tss/ecdsa/paillierproof.ts
// BitGo/BitGoJS (fix landed across PRs #3590, #3602, and #3634)

// Reject N if divisible by any small prime up to alpha = 319567
for (const prime of primesSmallerThan319567) {
  if (n % BigInt(prime) === BigInt(0)) {
    return false;
  }
}
// Verify the m Paillier challenge proofs
for (let i = 0; i < m; i++) {
  if (p[i] !== modPow(sigma[i], n, n)) {
    return false;
  }
}
return true;
```
