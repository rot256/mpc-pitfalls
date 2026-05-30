---
title: "tss-lib threshold EdDSA missing cofactor clearing"
category: input-validation
subcategory: "Curve Points Not Validated"
order: 2
date: 2020-11-13
primitives: [elliptic-curve, signature]
repository: https://github.com/bnb-chain/tss-lib
pr: 115
source:
  - name: "Baby Sharks"
    url: https://medium.com/zengo/baby-sharks-a3b9ceb4efe0
hidden: false
---

Standard EdDSA defends against small-subgroup attacks via bit clamping on the single-party secret scalar. The threshold EdDSA path in tss-lib applied no equivalent defense to supplied points received from peers, so as the ZenGo's [Baby Sharks](https://medium.com/zengo/baby-sharks-a3b9ceb4efe0) analysis showed, a malicious party could inject an order-8 torsion component into the joint public key so that $1/8$ of signing ceremonies verify, while the other will reject.

In the pre-fix tss-lib, the received commitment $R_j$ was constructed straight from peer-supplied coordinates and aggregated into the joint $R$ with no subgroup-membership step ([source](https://github.com/bnb-chain/tss-lib/blob/2f942010e2f18f6bfcec35265b73e0fdf33a1bf0/eddsa/signing/round_3.go#L52-L66)):

```go
// eddsa/signing/round_3.go — bnb-chain/tss-lib (pre-fix)
Rj, err := crypto.NewECPoint(tss.EC(), coordinates[0], coordinates[1])
if err != nil {
    return round.WrapError(errors.Wrapf(err, "NewECPoint(Rj)"), Pj)
}
// ... proof.Verify(Rj) checks knowledge of the discrete log, not subgroup ...
extendedRj := ecPointToExtendedElement(Rj.X(), Rj.Y())
R = addExtendedElements(R, extendedRj)
```

The remediation landed in [PR #115](https://github.com/bnb-chain/tss-lib/pull/115). It adds an `EightInvEight()` helper in `crypto/ecpoint.go` that multiplies by 8 then by $8^{-1} \bmod N$, projecting any input into the prime-order subgroup ([source](https://github.com/bnb-chain/tss-lib/blob/a8278131c426cd2e2f9f2ed3cf456b62fddfa49c/crypto/ecpoint.go#L87-L89)):

```go
// crypto/ecpoint.go — bnb-chain/tss-lib (post-fix)
var (
    eight    = big.NewInt(8)
    eightInv = new(big.Int).ModInverse(eight, edwards.Edwards().Params().N)
)

func (p *ECPoint) EightInvEight() *ECPoint {
    return p.ScalarMult(eight).ScalarMult(eightInv)
}
```

The helper is then applied to every received point. The patch at the signing site, mirroring the pre-fix excerpt above ([source](https://github.com/bnb-chain/tss-lib/blob/a8278131c426cd2e2f9f2ed3cf456b62fddfa49c/eddsa/signing/round_3.go#L52-L56)):

```go
// eddsa/signing/round_3.go — bnb-chain/tss-lib (post-fix)
Rj, err := crypto.NewECPoint(tss.EC(), coordinates[0], coordinates[1])
Rj = Rj.EightInvEight()
if err != nil {
    return round.WrapError(errors.Wrapf(err, "NewECPoint(Rj)"), Pj)
}
```
