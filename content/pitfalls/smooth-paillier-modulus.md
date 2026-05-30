---
title: "Non-Biprime Paillier Modulus"
class: cryptographic-primitives
hidden: false
order: 1
source: "rsa-moduli.md"
primitives: [paillier, homomorphic-encryption, zkp]
---


**What can go wrong.** Paillier cryptosystem relies on a biprime modulus $N = pq$ where $p$ and $q$ are large primes (often required to be safe primes, $p = 2p' + 1$ with $p'$ prime, for downstream proofs). When parties in an MPC protocol publish their own modulus, a receiver that skips biprimality and no-small-factor checks inherits whatever structure the sender chose, which enables key-recovery attacks against the protocols that use $N$.

**Security implication.** The BitForge attack (CVE-2023-33241, Fireblocks 2023): the
malicious $N_A = p_1 \cdots p_{16} \cdot q$ with each $p_i \approx 2^{16}$ lets the
attacker craft an out-of-range plaintext $k = N_A / p_i$ in each MtA call and forge
the range proof by brute-forcing a blinding factor in about $p_i \approx 2^{16}$
attempts. The victim's encrypted share leaks $x_B \bmod p_i$ per signing session;
after 16 sessions, CRT reconstructs the full $x_B$. Five major GG18/GG20 libraries
were affected at disclosure; CVSS score 9.6 (Critical).

**How to avoid.** Require every party publishing a Paillier key to accompany it with
two ZK proofs from [CGGMP21](https://eprint.iacr.org/2021/060):

- **Paillier-Blum Modulus proof** — proves $N = pq$ for primes $p \equiv q \equiv 3 \pmod 4$.
- **No-Small-Factor proof** — proves both prime factors satisfy $p, q > 2^{256}$.

Reject the participant if either proof fails to verify, before the modulus is stored
anywhere. The pair of proofs closes both the biprimality gap and the small-factor
gap.

**Example: tss-lib BitForge CVE-2023-33241.** Pre-v2.0.0 tss-lib stored incoming
Paillier keys with no biprimality check
([source](https://github.com/bnb-chain/tss-lib/blob/master/ecdsa/signing/round_1.go)):

```go
// FILE: ecdsa/signing/round_1.go — bnb-chain/tss-lib <= v1.3.5 (vulnerable)
// No validation that PaillierPKs[j].N is biprime or free of small factors.
cA, pA, err := round.key.PaillierPKs[round.PartyID().Index].EncryptAndReturnRandomness(kA)
// ... MtA proceeds with potentially malicious N
```

v2.0.0 ([GHSA-5cjx-95fx-68q9](https://github.com/advisories/GHSA-5cjx-95fx-68q9))
added both CGGMP21 proofs to the DKG phase:

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

Fireblocks' [BitForge disclosure](https://www.fireblocks.com/blog/bitforge-fireblocks-researchers-uncover-vulnerabilities-in-over-15-major-wallet-providers/)
named 15+ affected wallet providers. Apache Milagro had an additional aggravating
factor: its range-proof beta parameter was only 256 bits instead of ~2048, reducing the
number of signing sessions needed for full key extraction from 16 to about 1 —
practical against any single co-signing session.
