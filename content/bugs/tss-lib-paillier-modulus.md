---
title: "`bnb-chain/tss-lib` missing Paillier modulus validation (BitForge)"
category: cryptographic-primitives
subcategory: "Smooth or Non-Biprime Paillier Modulus"
order: 2
date: 2023-08-09
primitives: [paillier, homomorphic-encryption, zkp]
repository: https://github.com/bnb-chain/tss-lib
source:
  - name: "Fireblocks BitForge disclosure"
    url: https://www.fireblocks.com/blog/bitforge-fireblocks-researchers-uncover-vulnerabilities-in-over-15-major-wallet-providers/
  - name: "Fireblocks technical report"
    url: https://www.fireblocks.com/blog/gg18-and-gg20-paillier-key-vulnerability-technical-report
  - name: "GHSA-5cjx-95fx-68q9"
    url: https://github.com/advisories/GHSA-5cjx-95fx-68q9
cve:
  name: CVE-2023-33241
  url: https://nvd.nist.gov/vuln/detail/CVE-2023-33241
hidden: true
---

Pre-v2.0.0 [`bnb-chain/tss-lib`](https://github.com/bnb-chain/tss-lib)
stored incoming Paillier keys from co-signers with no biprimality or
no-small-factor check. A malicious co-signer could publish a structured
$N_A = p_1 \cdots p_{16} \cdot q$ and ride the missing validation through
MtA into share extraction (see the parent pitfall for the full attack
mechanic).

The vulnerable site is the MtA encryption call in
`ecdsa/signing/round_1.go`
([source](https://github.com/bnb-chain/tss-lib/blob/master/ecdsa/signing/round_1.go)):

```go
// FILE: ecdsa/signing/round_1.go — bnb-chain/tss-lib <= v1.3.5 (vulnerable)
// No validation that PaillierPKs[j].N is biprime or free of small factors.
cA, pA, err := round.key.PaillierPKs[round.PartyID().Index].EncryptAndReturnRandomness(kA)
// ... MtA proceeds with potentially malicious N
```

v2.0.0
([GHSA-5cjx-95fx-68q9](https://github.com/advisories/GHSA-5cjx-95fx-68q9))
added both [CGGMP21](https://eprint.iacr.org/2021/060) proofs to the DKG
phase:

```go
// FILE: ecdsa/keygen/round_2.go — bnb-chain/tss-lib v2.0.0 (fixed)
// Verify Paillier-Blum modulus (N = pq, Blum prime structure)
if ok := paillierBlumVerify(r1msg.PaillierBlumProof, Nj); !ok {
    return round.WrapError(fmt.Errorf("paillier blum proof failed"), Pj)
}
// Verify no small factors (p, q > 2^256)
if ok := noSmallFactorVerify(r1msg.NoSmallFactorProof, Nj); !ok {
    return round.WrapError(fmt.Errorf("no small factor proof failed"), Pj)
}
```

`bnb-chain/tss-lib` was one of five GG18/GG20 libraries named in
Fireblocks'
[BitForge disclosure](https://www.fireblocks.com/blog/bitforge-fireblocks-researchers-uncover-vulnerabilities-in-over-15-major-wallet-providers/),
with 15+ wallet providers affected at the time of public release.
