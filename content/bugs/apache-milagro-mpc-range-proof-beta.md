---
title: "Apache Milagro MPC: short range-proof beta + missing biprimality"
category: cryptographic-primitives
subcategory: "Smooth or Non-Biprime Paillier Modulus"
date: 2023-08-09
primitives: [paillier, homomorphic-encryption, zkp]
repository: https://github.com/apache/incubator-milagro-MPC
source:
  - name: "Fireblocks technical report"
    url: https://www.fireblocks.com/blog/gg18-and-gg20-paillier-key-vulnerability-technical-report
cve:
  name: CVE-2023-33241
  url: https://nvd.nist.gov/vuln/detail/CVE-2023-33241
hidden: true
---

Apache Milagro's MPC library
[`incubator-milagro-MPC`](https://github.com/apache/incubator-milagro-MPC)
implemented GG20-style ECDSA threshold signing and shipped two compounding
failures that together produced the most severe variant of the BitForge
class:

1. The same missing biprimality and no-small-factor checks on incoming
   Paillier moduli as the rest of the affected cohort
   ([CVE-2023-33241](https://nvd.nist.gov/vuln/detail/CVE-2023-33241)).
2. The MtA range-proof blinding parameter $\beta$ sized at only 256 bits,
   rather than the ~2048 bits that match the Paillier modulus.

In the standard BitForge attack against a library with the missing checks
alone, the attacker crafts a malicious modulus
$N_A = p_1 \cdots p_{16} \cdot q$ and harvests $x \bmod p_i$ over ~16
signing sessions. In Milagro, according to Fireblocks'
[technical report](https://www.fireblocks.com/blog/gg18-and-gg20-paillier-key-vulnerability-technical-report),
the undersized $\beta$ collapsed the work budget so far that the victim's
share could be extracted directly from honest signature transcripts of a
single co-signing session, without the attacker needing to craft a
malicious modulus at all. The malicious-modulus path remained available
as a faster amplification.

The undersized $\beta$ is visible directly in `src/mta.c` at tag `0.1`
([source](https://github.com/apache/incubator-milagro-MPC/blob/0.1/src/mta.c#L221-L283)):
the blinding scalar `z` is drawn modulo the secp256k1 curve order
(~256 bits) and `BETA` is serialized with length `EGS_SECP256K1` (32 bytes),
rather than being drawn from the much larger range required for the
range proof to actually hide $x$.

```c
// FILE: src/mta.c — apache/incubator-milagro-MPC tag 0.1 (vulnerable)
void MPC_MTA_SERVER(csprng *RNG, PAILLIER_public_key *PUB, octet *B,
                    octet *CA, octet *ZO, octet *R, octet *CB, octet *BETA)
{
    BIG_256_56 q;
    BIG_256_56 z;
    ...
    // Curve order
    BIG_256_56_rcopy(q, CURVE_Order_SECP256K1);
    ...
    // Random z value
    BIG_256_56_randomnum(z, q, RNG);     // z drawn mod curve order (~256 bits)
    BIG_256_56_toBytes(Z.val, z);
    Z.len = EGS_SECP256K1;                // 32 bytes, not Paillier-sized
    ...
    OCT_pad(&Z, FS_2048);                 // padded to 2048 bits but entropy is still 256 bits
    // beta = -z mod q
    BIG_256_56_sub(z, q, z);
    ...
    // Output beta
    BIG_256_56_toBytes(BETA->val, z);
    BETA->len = EGS_SECP256K1;            // beta size matches curve order, not N
}
```

The Apache Milagro MPC project has since been retired (the repo is
archived and carries a `RETIRED.txt` pointing to the Apache Incubator
project page).

Properly closing both failures requires (a) the two
[CGGMP21](https://eprint.iacr.org/2021/060) proofs on every co-signer's
Paillier modulus and (b) sizing the range-proof $\beta$ to match $N$
(typically ~2048 bits), not the curve order.
