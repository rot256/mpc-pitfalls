---
title: "`coinbase/kryptology` GG20 DKG ships secret shares unencrypted"
date: 2022-01-06
primitives: [secure-channel, paillier, homomorphic-encryption]
repository: https://github.com/coinbase/kryptology
issue: 29
---

GG20's
joint key-generation procedure (inherited from
[GG18](https://eprint.iacr.org/2019/114)) assumes the Round 2 P2P delivery of each
Shamir share $x_{ij}$ runs over a confidential point-to-point channel. The GG18/GG20
papers assume this private channel abstractly and leave its instantiation to the
deployment; Paillier encryption enters only in the signing-phase MtA, never for the
keygen shares.
The Coinbase library's GG20 implementation provides no confidentiality of its own and
returns the share as a bare struct field
([source](https://github.com/coinbase/kryptology/blob/master/pkg/tecdsa/gg20/participant/dkg_round2.go)):

```go
// FILE: pkg/tecdsa/gg20/participant/dkg_round2.go — coinbase/kryptology

type DkgRound2P2PSend struct {
    xij *v1.ShamirShare  // raw share — no encryption applied
}
// ...
p2PSend[id] = &DkgRound2P2PSend{ xij: dp.state.X[id-1] }
```

<!--An integrator filed [issue #29](https://github.com/coinbase/kryptology/issues/29) after
having to fork the library to make `xij` exportable for transmission, noting it "feels
unsafe to share in unencrypted form" and pointing out that Swingby's tss-lib fork
[Paillier-encrypts the share](https://github.com/SwingbyProtocol/tss-lib/blob/668d0061fadf08bf2ba9f7e9287516fc173b6b9c/ecdsa/keygen/round_3.go#L127-L133)
at the equivalent round.-->