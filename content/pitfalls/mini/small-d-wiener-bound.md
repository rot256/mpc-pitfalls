---
title: "Private Exponent $d$ Not Validated Against the Wiener Bound"
class: others
source: "rsa-moduli.md"
---

### Private Exponent $d$ Not Validated Against the Wiener Bound

<div class="pitfall-flags"><span class="flag flag-tbd">TBD example</span></div>

**What can go wrong.** If an RSA-style scheme uses a private exponent $d$ with
$d < N^{1/4}$, Wiener's continued-fractions attack recovers $d$ from the public $(N,
e)$ in polynomial time. [Boneh and Durfee](https://link.springer.com/chapter/10.1007/3-540-48910-X_1)
generalised this to $d < N^{0.292}$ using lattice reduction. In MPC threshold RSA, if
$d$ is derived from shares via a distribution that clusters it below the Wiener bound
— for instance, a small public exponent leading to $d$ skewed small — the effective
key length is far below the modulus size.

**Security implication.** Any outsider who observes the public modulus can recover
$d$, forge signatures, and decrypt ciphertexts. No interaction with honest parties is
required. For threshold deployments that use $d$ directly (threshold RSA signing), the
private key is effectively public.

**How to avoid.** Validate that the derived $d$ satisfies at least $d > N^{1/4}$ (the
Wiener bound) — and tighter, $d > N^{0.292}$ against Boneh–Durfee. For threshold key
generation, use a protocol that guarantees $d$ is sampled close to uniform on
$[1, \phi(N))$. Small public exponents $e$ (e.g., $e = 3$) should be avoided in
threshold settings where the resulting $d$ tends to be small.

**Example.** *TBD.* The Wiener / Boneh–Durfee bounds are classical and no specific
MPC-library CVE is pinned to this concern on this page.
