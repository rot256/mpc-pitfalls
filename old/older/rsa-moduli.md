---
title: "RSA-Style Moduli"
class: "RSA / Paillier Moduli"
order: 12
---

RSA-style moduli $N = pq$ appear in MPC primarily through **Paillier encryption**,
which underlies multiplicative-to-additive (MtA) conversion in threshold ECDSA
protocols such as GG18 and GG20. Each participant publishes a Paillier public key
during DKG, and other parties use it to encrypt shares and run Pedersen-style range
proofs under auxiliary bases $h_1, h_2$. The security of every downstream range proof
and decryption step rests on three properties of the modulus: it is a genuine biprime
with no small factors, the underlying primes are safe, and the auxiliary bases have no
small-order components. Violations do not trigger any abort — they silently degrade
the soundness of the surrounding proofs, and the receiver only notices after a key
share has been extracted.

### Private exponent $d$ not validated against the Wiener bound

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

### DLN-proof bases with order 2 or 4 accepted

**What can go wrong.** GG18/GG20 range proofs instantiate Pedersen commitments under
auxiliary bases $h_1, h_2 \in \mathbb{Z}_{\tilde N}^*$ and assume those bases generate
the same large subgroup. If an honest party accepts $h_1, h_2$ from a peer without any
cryptographic guarantee that neither base has small order, a malicious peer can supply
$h_1 = -1 \bmod \tilde N$ (order 2) or a small-order $h_2$. Pedersen commitments
$h_1^x h_2^r$ then collapse to $(-1)^x h_2^r$, leaking the parity of $x$ per
ciphertext; higher-order small bases leak more bits per use.

**Security implication.** An adversary chooses $h_1$ of order 2 and submits it as
auxiliary keygen input. In each subsequent signing MtA call, the range proof's
Pedersen commitment leaks $x \bmod 2$ of the victim's key share. By iterating with
crafted bases of increasing small order (2, 4, 8, …), the adversary reconstructs the
full share bit by bit. A degenerate variant provides $\tilde N = h_1 = h_2 = 1$,
making every range proof trivially verifiable — the adversary can claim any witness.

**How to avoid.** Accompany every $(h_1, h_2, \tilde N)$ broadcast with a **DLN proof**
that the sender knows $\alpha$ with $h_2 = h_1^{\alpha} \bmod \tilde N$, plus a
companion proof in the reverse direction ($h_1 = h_2^{\beta} \bmod \tilde N$). The
proof's soundness forces $h_1$ and $h_2$ to generate the same large subgroup, ruling
out small-order choices. Additionally require $h_1 \ne h_2$, and check that $\tilde N$
is at least a standard size (typically 2048 bits). For the modulus itself, see the
next mini-pitfall.

**Example: tss-lib CVE-2020-12118 — no DLN proofs in keygen.** In `bnb-chain/tss-lib`
before v1.2.0, round 2 of ECDSA keygen stored $h_1, h_2, \tilde N$ directly from the
incoming message without any proof
([source](https://github.com/bnb-chain/tss-lib/pull/89)):

```go
// FILE: ecdsa/keygen/round_2.go — bnb-chain/tss-lib < v1.2.0 (vulnerable)
for j, msg := range round.temp.kgRound1Messages {
    r1msg := msg.Content().(*KGRound1Message)
    round.save.PaillierPKs[j] = r1msg.UnmarshalPaillierPK()
    round.save.NTildej[j]     = r1msg.UnmarshalNTilde()           // ← no proof
    round.save.H1j[j], round.save.H2j[j] = r1msg.UnmarshalH1(), r1msg.UnmarshalH2()  // ← no proof
    round.temp.KGCs[j]        = r1msg.UnmarshalCommitment()
}
```

[PR #89](https://github.com/bnb-chain/tss-lib/pull/89) (merged March 5, 2020, released
as v1.2.0) added a `DlnProofVerifier` that runs two concurrent DLN proof checks
before accepting any party's bases:

```go
// FILE: ecdsa/keygen/round_2.go — bnb-chain/tss-lib >= v1.2.0 (fixed)
dlnVerifier := NewDlnProofVerifier(round.Concurrency())
for j, msg := range round.temp.kgRound1Messages {
    r1msg := msg.Content().(*KGRound1Message)
    H1j, H2j := r1msg.UnmarshalH1(), r1msg.UnmarshalH2()
    NTildej  := r1msg.UnmarshalNTilde()
    dlnVerifier.VerifyDLNProof1(round.temp.ssid, r1msg, H1j, H2j, NTildej,
        func(isValid bool) { /* abort if false */ })
    dlnVerifier.VerifyDLNProof2(round.temp.ssid, r1msg, H2j, H1j, NTildej,
        func(isValid bool) { /* abort if false */ })
    // Also check Paillier modulus is 2048 bits and h1 != h2
}
```

For the complementary concern that the factors of $\tilde N$ themselves must be safe
primes (otherwise even a sound DLN proof can be forged once the factorisation is
smooth), see the [Discrete Log Groups](../discrete-log-groups/) pitfall.

### Paillier modulus with small factors not rejected

**What can go wrong.** Even after DLN proofs close the $h_1, h_2$ gap above, the
Paillier modulus $N$ itself can be malformed. An adversary is free to publish $N = p_1
\cdot p_2 \cdots p_{16} \cdot q$ — a product of 16 small primes and one large prime —
rather than a genuine biprime $N = pq$. The receiver stores $N$ without a
**biprimality check** and uses it directly in MtA sub-protocols. The Paillier-based
range proof's soundness relies on $N$ being a biprime; with small factors, the proof
can be forged.

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

<!--
### Commit Timeline

| Date | Repository | Artifact | Description |
|------|-----------|----------|-------------|
| Oct 18, 2019 | [bnb-chain/tss-lib](https://github.com/bnb-chain/tss-lib) | [Issue #67](https://github.com/bnb-chain/tss-lib/issues/67) | Audit finding: `GenerateNTildei()` uses `rsa.GenerateMultiPrimeKey()` — not safe primes |
| ~Nov 2019 | [bnb-chain/tss-lib](https://github.com/bnb-chain/tss-lib) | [PR #68](https://github.com/bnb-chain/tss-lib/pull/68) | Fix: replace prime generation with dedicated safe-prime sampler |
| Mar 5, 2020 | [bnb-chain/tss-lib](https://github.com/bnb-chain/tss-lib) | [PR #89](https://github.com/bnb-chain/tss-lib/pull/89) / [commit `7b7c17e`](https://github.com/bnb-chain/tss-lib/commit/7b7c17e90504d5dad94b938e84fec690bb1ec311) | Fix (CVE-2020-12118): add DLN proofs for $h_1, h_2, \tilde{N}$ in keygen round 2; released as v1.2.0 |
| Jun 29, 2021 | — | [GHSA-399h-cmvp-qgx5](https://github.com/advisories/GHSA-399h-cmvp-qgx5) | CVE-2020-12118 publicly assigned and published in GitHub Advisory Database |
| Dec 2022 | — | — | Verichains begin reporting TSSHOCK issues privately |
| Mar 28, 2023 | [thorchain](https://gitlab.com/thorchain/thornode) | — | THORChain halts globally ($180M TVL) after receiving TSSHOCK α-shuffle PoC |
| May 5, 2023 | — | — | Fireblocks discovers CVE-2023-33241 (BitForge); 90-day responsible disclosure begins with 10+ vendors |
| Apr–Aug 2023 | Multiple | — | Verichains privately shares TSSHOCK with affected wallet custodians and vendors |
| Aug 9, 2023 | — | [NVD CVE-2023-33241](https://nvd.nist.gov/vuln/detail/CVE-2023-33241) | BitForge public disclosure at Black Hat USA; CVE-2023-33241 (CVSS 9.6) and CVE-2023-33242 published |
| Aug 10, 2023 | — | [GHSA-5cjx-95fx-68q9](https://github.com/advisories/GHSA-5cjx-95fx-68q9) | GitHub Advisory Database entry for CVE-2023-33241 published |
| Aug 10, 2023 | [verichains/tsshock](https://github.com/verichains/tsshock) | PoC release | TSSHOCK exploit code released at Black Hat USA 2023 |
| Aug 26, 2023 | [bnb-chain/tss-lib](https://github.com/bnb-chain/tss-lib) | v2.0.0 release | Fixes CVE-2023-33241 (Paillier-Blum + no-small-factor proofs) and TSSHOCK α-shuffle; **not backward-compatible** with v1.3.5 keys |
| Sep 1, 2023 | [threshold-network/tss-lib](https://github.com/threshold-network/tss-lib) | [GHSA-h24c-6p6p-m3vx](https://github.com/advisories/GHSA-h24c-6p6p-m3vx) | Second advisory (Critical) for tss-lib forks: ≤ v1.3.5 still lack biprimality check; no patch available at time of publication |

### Real-World Impact

**THORChain ($180M TVL, March 2023).** After Verichains sent a proof of concept for the α-shuffle TSSHOCK attack, THORChain's engineering team halted the entire mainnet to assess the risk to its TSS-based cross-chain bridge. The network was down long enough to affect live liquidity positions. THORChain ultimately disputed whether the attack was novel, but the halt itself confirmed that the threat was taken seriously at the operational level.

**BitForge — 15+ wallet providers (August 2023).** Fireblocks confirmed that all major open-source GG18/GG20 implementations were vulnerable to CVE-2023-33241 at the time of disclosure. Named providers included Coinbase (Wallet-as-a-Service), Binance custody, and ZenGo, among more than 15 others. Coinbase and ZenGo patched before public disclosure; Binance and most others were still exposed on the day of the Black Hat presentation. No theft from live production wallets was publicly confirmed, but Fireblocks released a [status checker tool](https://www.fireblocks.com/BitForge) to let projects self-assess. The CVSS score of 9.6 (Critical) reflects the low-interaction, remotely-exploitable nature of the attack.

**Apache Milagro (August 2023).** The Milagro implementation had an additional aggravating factor: its beta parameter (the range bound used in range proofs) was only 256 bits rather than the ~2048 bits required for security. This reduced the number of signing sessions needed for full key extraction from 16 to approximately 1, making the attack practical against any counter-party with a single co-signing session.

### Affected Libraries Summary

| Library | Vulnerability | Status |
|---------|--------------|--------|
| bnb-chain/tss-lib | CVE-2020-12118 | Fixed in v1.2.0 (PR #89) |
| bnb-chain/tss-lib | Unsafe Paillier primes | Fixed (PR #68) |
| bnb-chain/tss-lib | CVE-2023-33241 | Fixed in v2.0.0 |
| bnb-chain/tss-lib | TSSHOCK α-shuffle | Fixed in v2.0.0 |
| Safeheron/multi-party-ecdsa-cpp | CVE-2023-33241 | Fixed (f99c4e87) |
| ZenGo-X/multi-party-ecdsa | CVE-2023-33241 / TSSHOCK | Won't fix (unmaintained) |
| Taurus/multi-party-sig | TSSHOCK α-shuffle | Fixed |
| Axelar/tofn | TSSHOCK c-split | Not fixed (Aug 2023) |
| ING-Bank/threshold-signatures | TSSHOCK c-split | Not fixed (Aug 2023) |
| Apache Milagro | CVE-2023-33241 (256-bit beta) | Fixed post-disclosure |
| Multichain/fastMPC | TSSHOCK c-guess, α-shuffle | Fixed |
-->
