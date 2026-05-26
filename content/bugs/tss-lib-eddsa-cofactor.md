---
title: "tss-lib threshold EdDSA missing cofactor clearing (Baby Sharks)"
category: input-validation
subcategory: "Curve Points Not Validated"
order: 2
date: 2023-12-08
primitives: [elliptic-curve, signature]
repository: https://github.com/bnb-chain/tss-lib
issue: 283
source:
  - name: "Baby Sharks, ZenGo (Shlomovits)"
    url: https://medium.com/zengo/baby-sharks-a3b9ceb4efe0
hidden: false
---

Standard EdDSA defends against small-subgroup attacks via *bit clamping*:
secret scalars have their three lowest bits zeroed so that any scalar
multiplication strips the order-8 torsion component of Curve25519. The
threshold EdDSA path in tss-lib has no equivalent step on adversary-supplied
points received from peers, so a malicious party can inject a torsion
component into the joint public key, a partial nonce commitment, or a key
share.

ZenGo's [Baby Sharks](https://medium.com/zengo/baby-sharks-a3b9ceb4efe0)
analysis (Shlomovits, 2020) demonstrated the attack. A malicious party in
threshold EdDSA sends a key share $X_m = x_m \cdot B + T$ where $T$ is a
torsion point of order 8. The joint public key $Y = \sum X_i$ acquires the
extra torsion component:

```text
Conceptual threshold-EdDSA keygen without cofactor clearing
- Malicious party sends X_m = x_m*B + T where T is a torsion point (8*T = O).
- Honest parties compute joint key Y = Σ X_i = (Σ x_i)*B + T.
- Signing produces s such that s*B = R + c*Y = R + c*(X + T).
- Verification s*B == R + c*Y succeeds only when c*T == O, i.e. c ≡ 0 mod 8.
- Probability of signature acceptance per ceremony: 1/8.
```

Each ceremony's challenge $c$ is computed over a hash of the public state, so
the attacker observes whether the signature verifies and learns $c \bmod 8$
per successful path. Repeated ceremonies either silently deny service (honest
signatures rejected most of the time) or leak three bits of every successful
challenge to the attacker. Variants of the same primitive apply to round-1
commitments and partial signatures.

The fix is to multiply every externally-supplied point by the cofactor $h = 8$
at the wire boundary and reject if the result is the identity (the input was
a pure torsion point), or to switch the threshold protocol to
[Ristretto255](https://ristretto.group), which exposes only the prime-order
quotient group and makes torsion injection structurally impossible. The
single-party `crypto/ed25519` library handles this via bit clamping plus
explicit cofactor checks during verification; the threshold variant must
reproduce both steps at every input boundary.

tss-lib [Issue #283](https://github.com/bnb-chain/tss-lib/issues/283), opened
December 8, 2023, raises this as an open concern for the library's threshold
EdDSA path. No fix has been merged at the time of writing.
