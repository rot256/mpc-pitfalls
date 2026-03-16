---
title: "Zero Knowledge Proofs Not Bound to the Protocol Execution"
class: "Protocol"
order: 3
---

I.e. not embedding the unique context for the protocol _and_ given execution _and_ constructing party (and potentially receiving party).

### Example

CVE-2022-47930 (bnb-chain/tss-lib v1.x): the Schnorr proof of knowledge computed Fiat-Shamir challenges without any session identifier, party identity, or protocol context. The [hash input](https://github.com/bnb-chain/tss-lib/blob/14e70f2891f45aed785ab78ba9ecb8197a5674d1/crypto/schnorr/schnorr_proof.go#L30-L51) contained only the public key and the commitment:

```go
// crypto/schnorr/schnorr_proof.go — bnb-chain/tss-lib v1.x
func NewZKProof(x *big.Int, X *crypto.ECPoint) (*ZKProof, error) {
    ec := X.Curve()
    q := ec.Params().N
    g := crypto.NewECPointNoCurveCheck(ec, ecParams.Gx, ecParams.Gy)
    a := common.GetRandomPositiveInt(q)
    alpha := crypto.ScalarBaseMult(ec, a)
    // challenge does not include session ID or party identity
    cHash := common.SHA512_256i(X.X(), X.Y(), g.X(), g.Y(), alpha.X(), alpha.Y())
    c := common.RejectionSample(q, cHash)
    t := new(big.Int).Mul(c, x)
    t = common.ModInt(q).Add(a, t)
    return &ZKProof{Alpha: alpha, T: t}, nil
}
```

Valid proofs could be replayed across sessions; this undermined proof-of-knowledge guarantees needed to prevent rogue key attacks. The v2.0.0 fix added a `Session` parameter hashed into the challenge.

### References

- [CVE-2022-47930](https://nvd.nist.gov/vuln/detail/CVE-2022-47930).
- Kudelski Security, [Multiple CVEs in threshold cryptography implementations](https://research.kudelskisecurity.com/2023/03/23/multiple-cves-in-threshold-cryptography-implementations/), March 2023.
