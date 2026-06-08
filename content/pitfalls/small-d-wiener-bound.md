---
title: "Private Exponent $d$ Not Validated Against the Wiener Bound"
class: cryptographic-primitives
hidden: true
order: 10
source: "rsa-moduli.md"
primitives: [rsa]
---

**What can go wrong.** If an RSA-style scheme uses a private exponent $d$ with
$d < \frac{1}{3}N^{1/4}$, Wiener's continued-fractions attack recovers $d$ from
the public $(N, e)$ in polynomial time. [Boneh and Durfee](https://link.springer.com/chapter/10.1007/3-540-48910-X_1)
generalized this to $d < N^{0.292}$ using lattice reduction. In MPC threshold RSA,
the danger is a key-generation procedure or optimization that deliberately samples
or derives $d$ from a distribution clustered near zero.

**Security implication.** Any outsider who observes the public modulus can recover
$d$, forge signatures, and decrypt ciphertexts. No interaction with honest parties is
required. For threshold deployments that use $d$ directly (threshold RSA signing), the
private key is effectively public.

**How to avoid.** Never choose a small private exponent for performance. Validate
that the derived $d$ is outside the small-exponent attack range: at minimum above
the Wiener region $d < \frac{1}{3}N^{1/4}$, and conservatively above the
Boneh-Durfee region $d < N^{0.292}$.

**Example: Plaid CTF RSA key with a small private exponent
([Cryptologie, 2015](https://www.cryptologie.net/posts/small-rsa-private-key-problem/)).**
The Plaid CTF challenge published several RSA public triples $(N, e, c)$, one of
which had a private exponent small enough to recover from the public key using a
Wiener/Boneh-Durfee-style attack. This is a didactic CTF example rather than a
deployed MPC-library incident, but it cleanly illustrates the failure mode: once
$d$ falls below the small-private-exponent bounds, the public key alone is enough
to recover the private exponent.
