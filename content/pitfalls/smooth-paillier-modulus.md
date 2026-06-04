---
title: "Smooth or Non-Biprime Paillier Modulus"
class: cryptographic-primitives
hidden: false
order: 1
source: "rsa-moduli.md"
primitives: [paillier, homomorphic-encryption, zkp]
bugs: [safeheron-mpc-paillier-biprimality, apache-milagro-mpc-range-proof-beta, bitgo-tss-paillier-biprimality, tss-lib-paillier-modulus]
display: [safeheron-mpc-paillier-biprimality]
---


**What can go wrong.** The Paillier cryptosystem relies on a biprime modulus $N = pq$ where $p$ and $q$ are large primes, often required to be safe primes, $p = 2p' + 1$ with $p'$ prime. When parties in an MPC protocol publish their own modulus, skipping biprimality checks lets a malicious sender pick a structured $N$ that enables key-recovery attacks against the protocols that use it.

**Security implication.** The [BitForge attack](https://www.fireblocks.com/blog/bitforge-fireblocks-researchers-uncover-vulnerabilities-in-over-15-major-wallet-providers/) refers to a [collection of zero-day vulnerabilities discovered by Fireblocks researchers that impact MPC wallets](https://eprint.iacr.org/2023/1234). Part of these vulnerability involves skipping the biprimality and no-small-factor checks on the Paillier modulus in the GG18 & GG20 protocols, which led to a vulnerability on the shared key ([CVE-2023-33241](https://nvd.nist.gov/vuln/detail/CVE-2023-33241), [technical report](https://www.fireblocks.com/blog/gg18-and-gg20-paillier-key-vulnerability-technical-report)). The attacker chooses $N_A = p_1 \cdots p_{16} \cdot q$ with each $p_i \approx 2^{16}$ (small enough to brute-force the range proof), then crafts an out-of-range plaintext $k = N_A / p_i$ in each MtA call and forges the range proof by brute-forcing a blinding factor in about $p_i \approx 2^{16}$ attempts. The victim's encrypted share leaks $x \bmod p_i$ per signing session; after 16 sessions, CRT reconstructs the full $x$.

**How to avoid.** Require every party publishing a Paillier key to accompany it with two ZK proofs from [CGGMP21](https://eprint.iacr.org/2021/060): a Paillier-Blum Modulus proof, which proves $N = pq$ for primes $p \equiv q \equiv 3 \pmod 4$, and a No-Small-Factor proof, which proves both prime factors satisfy $p, q > 2^{256}$. Some deployments additionally require $p$ and $q$ to be safe primes ($p = 2p' + 1$ with $p'$ prime). Reject the participant if either proof fails to verify, before the modulus is stored anywhere.