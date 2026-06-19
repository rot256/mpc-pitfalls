---
title: "`bnb-chain/tss-lib` missing Paillier modulus validation (BitForge)"
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
---

Pre-v2.0.0 [`bnb-chain/tss-lib`](https://github.com/bnb-chain/tss-lib)
stored incoming Paillier keys from co-signers with no biprimality or
no-small-factor check. A malicious co-signer could publish a structured
$N_A = p_1 \cdots p_{16} \cdot q$ and ride the missing validation through
MtA into share extraction (see the parent pitfall for the full attack
mechanic).

The MtA call in `ecdsa/signing/round_1.go`
([source](https://github.com/bnb-chain/tss-lib/blob/v1.3.5/ecdsa/signing/round_1.go#L66))
proceeds with Paillier moduli that keygen never required a proof for:

```go
// FILE: ecdsa/signing/round_1.go — bnb-chain/tss-lib v1.3.5 (vulnerable)
// Pre-v2.0.0 keygen accepted each co-signer's Paillier modulus with no
// biprimality or no-small-factor proof, so MtA runs with moduli that were
// never proven well-formed.
cA, pi, err := mta.AliceInit(round.Params().EC(), round.key.PaillierPKs[i], k,
    round.key.NTildej[j], round.key.H1j[j], round.key.H2j[j])
```

v2.0.0
([GHSA-5cjx-95fx-68q9](https://github.com/advisories/GHSA-5cjx-95fx-68q9))
added both [CGGMP21](https://eprint.iacr.org/2021/060) proofs to the DKG phase:
each party generates a no-small-factor (`facproof`) and a Paillier-Blum
(`modproof`) proof of its own modulus, which counterparties verify in a later
round before accepting the key
([source](https://github.com/bnb-chain/tss-lib/blob/v2.0.0/ecdsa/keygen/round_2.go#L119-L148)):

```go
// FILE: ecdsa/keygen/round_2.go — bnb-chain/tss-lib v2.0.0 (fixed)
// Each party proves its Paillier modulus is well-formed; counterparties verify
// these proofs in a later round before accepting the key.
facProof, err = facproof.NewProof(ContextI, round.EC(), round.save.PaillierSK.N, round.save.NTildej[j],
    round.save.H1j[j], round.save.H2j[j], round.save.PaillierSK.P, round.save.PaillierSK.Q)  // no-small-factor
// ...
modProof, err = modproof.NewProof(ContextI, round.save.PaillierSK.N,
    round.save.PaillierSK.P, round.save.PaillierSK.Q)  // Paillier-Blum modulus
```

`bnb-chain/tss-lib` was one of five GG18/GG20 libraries named in
Fireblocks'
[BitForge disclosure](https://www.fireblocks.com/blog/bitforge-fireblocks-researchers-uncover-vulnerabilities-in-over-15-major-wallet-providers/),
with 15+ wallet providers affected at the time of public release.