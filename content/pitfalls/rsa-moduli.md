---
title: "RSA-Style Moduli"
class: "Cryptographic Primitive"
order: 6
---

- Not validating that the private key $d>N^{\frac{1}{4}}$.
- Not validating that a base element has order 2 or 4.

#### Recommendations

When used in custom protocols it is strongly recommended to ensure the following as well:

- $p$ and $q$ are safe primes.
- $p$ and $q$ are strong primes.
- If the group is used for signatures, then PSS padding is used.
- If the group is used for encryption then OAEP is used.

### Example

In bnb-chain/tss-lib < v1.2.0 (CVE-2020-12118), keygen [round 2](https://github.com/bnb-chain/tss-lib/blob/4fcd04b0ce5527ece51afa70c7852b5fd03b120c/ecdsa/keygen/round_2.go#L22-L44) stored $h_1$, $h_2$, and $\tilde{N}$ from other parties without any discrete-log proof verification:

```go
// ecdsa/keygen/round_2.go — bnb-chain/tss-lib v1.1.1
for j, msg := range round.temp.kgRound1Messages {
    r1msg := msg.Content().(*KGRound1Message)
    round.save.PaillierPKs[j] = r1msg.UnmarshalPaillierPK()
    round.save.NTildej[j] = r1msg.UnmarshalNTilde()
    round.save.H1j[j], round.save.H2j[j] = r1msg.UnmarshalH1(), r1msg.UnmarshalH2()
    round.temp.KGCs[j] = r1msg.UnmarshalCommitment()
}
```

A malicious party could supply arbitrary $h_1$, $h_2$, $\tilde{N}$ values, compromising the zero-knowledge proofs that rely on these parameters.

- Even after the v1.2.0 fix (which added DLN proofs), the Paillier modulus $N$ itself was still accepted without a biprimality check. CVE-2023-33241 (BitForge, CVSS 9.1) exploited this: an attacker constructs $N = p_1 \cdots p_{16} \cdot q$ with small $p_i$, forges range proofs, and extracts 16 bits of the victim's key share per signing session. Five libraries were affected.

### References

- Fireblocks, [BitForge: Fireblocks Research Uncovers Vulnerabilities in Over 15 Major MPC Wallets](https://www.fireblocks.com/blog/bitforge-fireblocks-researchers-uncover-vulnerabilities-in-over-15-major-wallet-providers/), August 2023.
- [CVE-2023-33241](https://nvd.nist.gov/vuln/detail/CVE-2023-33241), [CVE-2020-12118](https://nvd.nist.gov/vuln/detail/CVE-2020-12118).
- [GHSA-399h-cmvp-qgx5](https://github.com/advisories/GHSA-399h-cmvp-qgx5).
- PoC: [fireblocks-labs/safeheron-gg20-exploit-poc](https://github.com/fireblocks-labs/safeheron-gg20-exploit-poc).

---

# DRAFT RSA-Style Moduli

RSA-style moduli, integers $N = pq$, appear in MPC primarily through **Paillier encryption**, which
underlies multiplicative-to-additive (MtA) conversion in threshold ECDSA protocols such as GG18 and
GG20. In these protocols every participant publishes a Paillier public key $N_i$ during distributed
key generation (DKG), and other parties use $N_i$ to encrypt their secret shares and run
zero-knowledge range proofs against them. The security guarantees of the whole protocol rest on two
assumptions about each modulus:

1. $N$ is a **biprime** — the product of exactly two large, secret primes $p$ and $q$.
2. Both $p$ and $q$ are **safe primes** (i.e., $p = 2p' + 1$ and $q = 2q' + 1$ for primes $p', q'$),
   which ensures the Paillier group has the structure required by the ring-LWE and discrete-log
   hardness assumptions embedded in the surrounding ZK proofs.

Violations of either property do not trigger a protocol abort — they silently degrade the security
of every party who accepts the malformed modulus. The attacker can then extract secret key shares
across a small number of signing sessions.

Additionally, auxiliary parameters $h_1, h_2 \in \mathbb{Z}_{N^*}$ are published alongside each
Paillier key to support Pedersen-style range proofs. The security of those proofs requires a
discrete-log proof that $h_1$ and $h_2$ generate the same subgroup modulo $N$ and that neither has
small order (order 2 or 4 in particular). Accepting these parameters without verification allows
an adversary to trivially satisfy any range proof, bypassing the bound on the witness.

### Example 1: Missing DLN Proofs for $h_1$, $h_2$, $\tilde{N}$ (CVE-2020-12118)

In GG20 key generation each party broadcasts a Paillier public key together with two
auxiliary generators $h_1, h_2$ and a secondary modulus $\tilde{N}$ that are used to instantiate
Pedersen commitments inside range proofs. The parameters must satisfy a **discrete-log-no-op (DLN)**
relation: the sender must know $\alpha$ such that $h_2 = h_1^\alpha \bmod \tilde{N}$,
which ensures that an adversary cannot choose $h_1$ or $h_2$ with a special structure (e.g., order
2 or 4) that would allow them to forge range proofs later.

In `bnb-chain/tss-lib` before v1.2.0, round 2 of ECDSA keygen stored these parameters directly
from the incoming message without verifying any such proof:

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

**Attack.** A malicious party constructs $h_1$ (or $h_2$) with order 2 or 4 in
$\mathbb{Z}_{\tilde{N}}^*$. Because the range proofs in GG20 compute
$\Gamma = h_1^x h_2^r \bmod \tilde{N}$, setting $h_1 = -1 \bmod \tilde{N}$ (order 2)
collapses the Pedersen commitment to $(-1)^x h_2^r$, which the attacker can invert to
recover $x \bmod 2$ from each ciphertext. Repeating with crafted bases of increasing order
allows full extraction of the victim's key share bit-by-bit. Alternatively, the attacker
provides $\tilde{N} = h_1 = h_2 = 1$, making every range proof trivially satisfied, and then
uses the resulting proofs to claim an arbitrary witness.

**Remediation.** PR [#89](https://github.com/bnb-chain/tss-lib/pull/89) (merged March 5, 2020,
released in v1.2.0) added a `DlnProofVerifier` that runs two concurrent DLN proof checks
before accepting any party's parameters:

```go
// FILE: ecdsa/keygen/round_2.go — bnb-chain/tss-lib >= v1.2.0 (fixed)

dlnVerifier := NewDlnProofVerifier(round.Concurrency())

for j, msg := range round.temp.kgRound1Messages {
    r1msg := msg.Content().(*KGRound1Message)
    H1j, H2j   := r1msg.UnmarshalH1(), r1msg.UnmarshalH2()
    NTildej     := r1msg.UnmarshalNTilde()

    // Verify proof that h2 = h1^alpha mod NTilde (DLN proof 1)
    dlnVerifier.VerifyDLNProof1(round.temp.ssid, r1msg, H1j, H2j, NTildej,
        func(isValid bool) { /* abort if false */ })

    // Verify proof that h1 = h2^beta mod NTilde (DLN proof 2)
    dlnVerifier.VerifyDLNProof2(round.temp.ssid, r1msg, H2j, H1j, NTildej,
        func(isValid bool) { /* abort if false */ })

    // Also check Paillier modulus is 2048 bits and h1 != h2
    ...
}
```

### Example 2: Unsafe Primes in Paillier Key Generation (Issue #67)

A separate audit finding (Kudelski Security, October 2019, issue
[#67](https://github.com/bnb-chain/tss-lib/issues/67)) identified that the helper function
`GetRandomGeneratorOfTheQuadraticResidue()` internally assumes its inputs are **safe primes**
($p = 2p' + 1$), but the primes supplied by `GenerateNTildei()` came from Go's standard
`rsa.GenerateMultiPrimeKey()`, which generates ordinary RSA primes with no special structure:

```go
// FILE: ecdsa/keygen/round_1.go — vulnerable (pre-fix)

// rsa.GenerateMultiPrimeKey produces arbitrary primes, NOT safe primes.
// GetRandomGeneratorOfTheQuadraticResidue() silently proceeds with the
// wrong group structure — its DLN proof is only sound for safe-prime groups.
p1, _ := rsa.GenerateMultiPrimeKey(rand.Reader, 2, safePrimeBitLen)
NTildei := new(big.Int).Mul(p1.Primes[0], p1.Primes[1])
h1i, h2i = crypto.GetRandomGeneratorOfTheQuadraticResidue(NTildei, ...)
```

**Attack.** When $p$ and $q$ in $\tilde{N} = pq$ are not safe primes, the order of the
multiplicative group $\mathbb{Z}_{\tilde{N}}^*$ has many small factors. An adversary who
knows this factorization (or brute-forces it due to the small-factor structure) can compute
discrete logarithms modulo each small factor and combine them via CRT, breaking the DLN
proof's soundness. In practice this means a proof of the form $h_2 = h_1^\alpha$ can be
forged with negligible work once the group order is smooth.

**Remediation.** PR [#68](https://github.com/bnb-chain/tss-lib/pull/68) replaced the prime
generation with a dedicated safe-prime sampler, ensuring $p$ and $q$ satisfy $p = 2p'+1$ and
$q = 2q'+1$ for large primes $p', q'$. The audit additionally required a minimum gap
$|p - q| \ge 2^{1020}$ to prevent square-root factorization attacks.

### Example 3: Malicious Paillier Modulus with Small Factors — BitForge (CVE-2023-33241)

Even after the DLN-proof fix landed in v1.2.0, the Paillier modulus $N$ itself was still
accepted without a **biprimality check**. Any party is free to publish $N = p_1 \cdots p_{16} \cdot q$
— a product of 16 small ~16-bit primes and one large prime — rather than a genuine $N = pq$.
The receiving parties store it and use it in MtA sub-protocols without verification.

The attack exploits the MtA ("multiplicative-to-additive") conversion step in GG18/GG20
signing, where party $A$ holds Paillier-encrypted value $\mathsf{Enc}_{N_A}(k_A)$ and
party $B$ contributes an additive share. In each MtA call $B$ must prove
that its plaintext lies in a prescribed range — but the range proof relies on the
soundness of Paillier, which breaks when $N$ has small factors.

**Attack (Case 1 — 16 signatures).**

1. Malicious party $A$ constructs $N_A = p_1 \cdots p_{16} \cdot q$ where each $p_i$ is a
   distinct 16-bit prime.
2. In each MtA call for signing session $i$, $A$ sets $k = N_A / p_i$ (an integer roughly
   2032 bits long, violating the expected 256-bit range), then forges the range proof by
   brute-forcing a blinding factor $\gamma$ until $e \equiv 0 \pmod{p_i}$ — possible in
   about $p_i \approx 2^{16}$ attempts.
3. Victim party $B$ encrypts its share $x_B$ under $N_A$ and sends the ciphertext
   $c = \mathsf{Enc}_{N_A}(k \cdot x_B + r)$. Because $k \equiv 0 \pmod{p_i}$, decryption
   modulo $p_i$ yields $c \equiv r \pmod{p_i}$, from which $A$ derives:
   $$x_B \bmod p_i \;=\; \frac{\alpha - (\alpha \bmod (N_A/p_i))}{N_A/p_i}$$
4. After 16 signing sessions (one per $p_i$), $A$ applies the Chinese Remainder Theorem to
   reconstruct $x_B$ completely, obtaining $B$'s secret key share.

The following code snippet illustrates what should have been checked on receipt:

```go
// FILE: ecdsa/signing/round_1.go — bnb-chain/tss-lib <= v1.3.5 (vulnerable)

// No validation that PaillierPKs[j].N is biprime or free of small factors.
// The modulus is used directly in MtA:
cA, pA, err := round.key.PaillierPKs[round.PartyID().Index].EncryptAndReturnRandomness(kA)
// ... MtA proceeds with potentially malicious N
```

**Remediation.** The fix (shipped in `bnb-chain/tss-lib` v2.0.0,
[GHSA-5cjx-95fx-68q9](https://github.com/advisories/GHSA-5cjx-95fx-68q9)) added two new
ZK proofs from [CGGMP21](https://eprint.iacr.org/2021/060) to the DKG phase:

- **Paillier-Blum Modulus proof** — a ZK proof that $N = pq$ for primes $p \equiv q \equiv 3 \pmod 4$.
- **No-Small-Factor proof** — a ZK proof that both factors satisfy $p, q > 2^{256}$.

Any party that cannot supply both proofs is rejected before their Paillier key is stored:

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

### Example 4: TSSHOCK — Forged DLN Proofs via α-Shuffle and c-Split

Verichains' **TSSHOCK** research (disclosed at Black Hat USA, August 2023) found that even
correct use of the DLN proof API could be defeated by manipulating the proof's internal
hash computation. Three distinct attack vectors were identified; the two most directly
relevant to RSA moduli are **α-shuffle** and **c-split**.

**α-shuffle.** The DLN proof in several implementations concatenated the challenge inputs
without a length delimiter:

```go
// FILE: crypto/dlnproof/proof.go — bnb-chain/tss-lib (vulnerable encoding)

// hash inputs are concatenated as raw bytes; no length prefix separates them.
// ["a$", "b"] and ["a", "$b"] produce the same hash.
msg := append(alpha.Bytes(), t.Bytes()...)
msg  = append(msg, NTilde.Bytes()...)
e    = hash(msg)
```

An adversary who controls multiple $\alpha$ values can find a pair that collide modulo
the challenge, then reuse one proof across different DLN statements — effectively forging
the proof for a maliciously constructed $h_1$ or $h_2$.

**c-split.** In optimized 256-bit-challenge variants of the DLN proof, the group order
$\phi(\tilde{N})$ is composite (not prime), so the challenge $e$ may share a factor with
$\phi(\tilde{N})$. When $\gcd(e, \phi(\tilde{N})) > 1$, the modular inverse of $e$ does
not exist, yet the proof verification equation $h_2 \equiv h_1^{e^{-1} \bmod \phi(\tilde{N})}$
still passes if the prover exploits the resulting lattice structure. A single malicious party
can extract the victim's full key share in as few as **1–2 signing sessions** using this
technique on the unpatched implementations listed in the table below.

**Remediation.** The fix for α-shuffle requires **length-prefixed** or otherwise injective
encoding of all hash inputs (e.g., using `hash.Write(len(alpha))` before `hash.Write(alpha)`).
The fix for c-split requires sampling the DLN challenge from a prime-order group or verifying
$\gcd(e, \phi(\tilde{N})) = 1$ before proceeding.

### Affected Libraries Summary

| Library | Vulnerability | Status | Notes |
|---------|--------------|--------|-------|
| [bnb-chain/tss-lib](https://github.com/bnb-chain/tss-lib) | CVE-2020-12118: missing DLN proofs | Fixed in v1.2.0 (Mar 2020) | PR #89 |
| [bnb-chain/tss-lib](https://github.com/bnb-chain/tss-lib) | Unsafe Paillier primes | Fixed (Oct 2019) | PR #68, Issue #67 |
| [bnb-chain/tss-lib](https://github.com/bnb-chain/tss-lib) | CVE-2023-33241: no biprimality/small-factor proof | Fixed in v2.0.0 | GHSA-5cjx-95fx-68q9 |
| [bnb-chain/tss-lib](https://github.com/bnb-chain/tss-lib) | TSSHOCK α-shuffle | Fixed in v2.0.0 | — |
| [Safeheron/multi-party-ecdsa-cpp](https://github.com/Safeheron/multi-party-ecdsa-cpp) | CVE-2023-33241 | Fixed (commit f99c4e87) | — |
| [ZenGo-X/multi-party-ecdsa](https://github.com/ZenGo-X/multi-party-ecdsa) | CVE-2023-33241 | Won't fix (unmaintained) | — |
| [ZenGo-X/multi-party-ecdsa](https://github.com/ZenGo-X/multi-party-ecdsa) | TSSHOCK c-split | Won't fix (unmaintained) | — |
| [Taurus/multi-party-sig](https://github.com/taurusgroup/multi-party-sig) | TSSHOCK α-shuffle | Fixed | — |
| [Axelar/tofn](https://github.com/axelarnetwork/tofn) | TSSHOCK c-split | Not fixed (as of Aug 2023) | — |
| [ING-Bank/threshold-signatures](https://github.com/ing-bank/threshold-signatures) | TSSHOCK c-split | Not fixed (as of Aug 2023) | — |
| [Apache Milagro/incubator-milagro-crypto](https://github.com/apache/incubator-milagro-crypto) | CVE-2023-33241 (256-bit beta) | Fixed post-disclosure | Critical: beta only 256 bits |
| Multichain/fastMPC | TSSHOCK c-guess, α-shuffle | Fixed | — |

### Commit Timeline

| Date | Repository | Artifact | Description |
|------|-----------|----------|-------------|
| Oct 18, 2019 | [bnb-chain/tss-lib](https://github.com/bnb-chain/tss-lib) | [Issue #67](https://github.com/bnb-chain/tss-lib/issues/67) | Audit finding: `GenerateNTildei()` uses `rsa.GenerateMultiPrimeKey()` — not safe primes; `GetRandomGeneratorOfTheQuadraticResidue()` assumes safe primes |
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
| Aug 26, 2023 | [bnb-chain/tss-lib](https://github.com/bnb-chain/tss-lib) | v2.0.0 release | Fixes CVE-2023-33241 (Paillier-Blum + no-small-factor proofs from CGGMP21) and TSSHOCK α-shuffle; adds session-ID binding to prevent replay attacks; **not backward-compatible** with v1.3.5 keys |
| Sep 1, 2023 | [threshold-network/tss-lib](https://github.com/threshold-network/tss-lib) | [GHSA-h24c-6p6p-m3vx](https://github.com/advisories/GHSA-h24c-6p6p-m3vx) | Second advisory (Critical) for tss-lib forks: ≤ v1.3.5 still lack biprimality check; no patch available at time of publication |

### Real-World Impact

**THORChain ($180M TVL, March 2023).** After Verichains sent a proof of concept for the
α-shuffle TSSHOCK attack, THORChain's engineering team halted the entire mainnet to assess
the risk to its TSS-based cross-chain bridge. The network was down long enough to affect
live liquidity positions. THORChain ultimately disputed whether the attack was novel, but
the halt itself confirmed that the threat was taken seriously at the operational level.

**BitForge — 15+ wallet providers (August 2023).** Fireblocks confirmed that all major
open-source GG18/GG20 implementations were vulnerable to CVE-2023-33241 at the time of
disclosure. Named providers included Coinbase (Wallet-as-a-Service), Binance custody,
and ZenGo, among more than 15 others. Coinbase and ZenGo patched before public disclosure;
Binance and most others were still exposed on the day of the Black Hat presentation. No
theft from live production wallets was publicly confirmed, but Fireblocks released a
[status checker tool](https://www.fireblocks.com/BitForge) to let projects self-assess.
The CVSS score of 9.6 (Critical) reflects the low-interaction, remotely-exploitable nature
of the attack.

**Apache Milagro (August 2023).** The Milagro implementation had an additional aggravating
factor: its beta parameter (the range bound used in range proofs) was only 256 bits rather
than the ~2048 bits required for security. This reduced the number of signing sessions
needed for full key extraction from 16 to approximately 1, making the attack practical
against any counter-party with a single co-signing session.
