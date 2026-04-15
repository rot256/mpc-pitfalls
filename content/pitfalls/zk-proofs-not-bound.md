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

---

# DRAFT Zero Knowledge Proofs Not Bound to the Protocol Execution

A ZK proof embedded in an MPC protocol is only meaningful if it is inseparably tied to the
*specific* execution that produced it. Concretely, a Fiat-Shamir proof generated during
key-generation session $A$ must not be accepted as valid during signing session $B$, must
not be re-usable by a different party than the one who computed it, and must not be
malleable through the omission of committed values. When the challenge hash omits any of:

- the **session identifier** (`ssid`) binding the proof to this run of the protocol,
- the **party identity** of the prover,
- the **full set of committed values** that appear in the verification equation,

the proof becomes transferable and the Fiat-Shamir transformation's soundness is broken in
the multi-session setting.

This is distinct from the UC session-ID issue (which concerns the overall protocol
transcript): here the failure is local to the proof construction itself and can be exploited
even when only a single session runs, provided the adversary can observe and replay
individual proof messages.

### Example 1: Schnorr Proof of Knowledge Without Session Binding — CVE-2022-47930

The Schnorr PoK in `bnb-chain/tss-lib` implements GG18 Fig. 16: party $P_i$ proves
knowledge of its secret key share $x_i$ by sending $(R = g^k, s = k + c \cdot x_i)$ where
$c$ is a Fiat-Shamir challenge. In v1.x the challenge is derived solely from the public key
and the commitment:

```go
// FILE: crypto/schnorr/schnorr_proof.go — bnb-chain/tss-lib v1.3.5 (vulnerable)
// ([source](https://github.com/bnb-chain/tss-lib/blob/v1.3.5/crypto/schnorr/schnorr_proof.go#L30-L51))

func NewZKProof(x *big.Int, X *crypto.ECPoint) (*ZKProof, error) {
    // ...
    a := common.GetRandomPositiveInt(q)
    alpha := crypto.ScalarBaseMult(ec, a)

    // Challenge includes only public key X and commitment alpha — no session ID,
    // no party identity, no protocol context.
    cHash := common.SHA512_256i(X.X(), X.Y(), g.X(), g.Y(), alpha.X(), alpha.Y())
    c := common.RejectionSample(q, cHash)

    t := common.ModInt(q).Add(a, new(big.Int).Mul(c, x))
    return &ZKProof{Alpha: alpha, T: t}, nil
}
```

The `Verify` function recomputes the identical challenge, so an adversary who intercepts
$(\alpha, t)$ from party $P_i$ in session $A$ can present the same pair in session $B$ and
it will pass verification against the same public key $X_i$.

**Attack (cross-session replay / rogue-key).** The NVD description of
[CVE-2022-47930](https://nvd.nist.gov/vuln/detail/CVE-2022-47930) states: *"the Schnorr
proof of knowledge … does not utilize a session id, context, or random nonce in the
generation of the challenge. This could allow a malicious user or an eavesdropper to replay
a valid proof sent in the past."* Concretely:

1. Adversary $\mathcal{A}$ acts as party $P_m$ in key-generation session $A$ and records
   the Schnorr proof $(\alpha^{(A)}, t^{(A)})$ broadcast by honest party $P_i$.
2. In a new signing session $B$ where $P_i$'s participation is required, $\mathcal{A}$
   replays $(\alpha^{(A)}, t^{(A)})$ as $P_m$'s proof.
3. Honest verifiers recompute $c = H(X_m, g, \alpha^{(A)})$ and check
   $t^{(A)} \cdot G \stackrel{?}{=} \alpha^{(A)} + c \cdot X_m$. Because $X_m = X_i$ and
   the proof was valid in session $A$, the check passes.
4. $\mathcal{A}$ has authenticated as $P_i$ without knowing $x_i$, breaking
   proof-of-knowledge and enabling rogue-key key substitution.

**Remediation.** [PR #256](https://github.com/bnb-chain/tss-lib/pull/256) (commit
[`1a14f3ac`](https://github.com/bnb-chain/tss-lib/commit/1a14f3ac9e), merged August 23,
2023) added a `Session []byte` parameter that is prepended — via the domain-separating
`SHA512_256i_TAGGED` — to every proof challenge ([source](https://github.com/bnb-chain/tss-lib/blob/v2.0.0/crypto/schnorr/schnorr_proof.go)):

```go
// FILE: crypto/schnorr/schnorr_proof.go — bnb-chain/tss-lib v2.0.0 (fixed)
// ([source](https://github.com/bnb-chain/tss-lib/blob/v2.0.0/crypto/schnorr/schnorr_proof.go))

func NewZKProof(Session []byte, x *big.Int, X *crypto.ECPoint) (*ZKProof, error) {
    // ...
    // Session is derived from public protocol parameters of this run;
    // a proof from session A will produce a different challenge in session B.
    cHash := common.SHA512_256i_TAGGED(Session, X.X(), X.Y(), g.X(), g.Y(), alpha.X(), alpha.Y())
    c := common.RejectionSample(q, cHash)
    // ...
}
```

The same fix was applied to `ZKVProof` (Fig. 17) in the same file, and to all CGGMP21
proof types added in v2.0.0 (`facproof`, `modproof`, `mta/proofs.go`), each of which
accepts `Session []byte` as its first argument.

### Example 2: Missing Committed Value in MtA Proof Hash — tss-lib Issue #42

The MtA ("multiplicative-to-additive") sub-protocol requires Bob to prove that his
encrypted value $x$ satisfies $X = g^x$ (the "with check" variant, `ProofBobWC`). The
verification equation for this proof involves five public values — $X$, $c_1$, $c_2$, the
randomized commitment $u = g^\alpha$, and several Pedersen commitments — but the original
Fiat-Shamir hash construction omitted $u$:

```go
// FILE: crypto/mta/proofs.go — bnb-chain/tss-lib (vulnerable, pre-PR #43)
// ([source](https://github.com/bnb-chain/tss-lib/issues/42))

// Bob's "with check" proof (MtAwc, GG18 Fig. 11).
// u = g^alpha is computed but NOT included in the challenge hash.
if X != nil {
    eHash = common.SHA512_256i(
        append(pk.AsInts(), X.X(), X.Y(), c1, c2, z, zPrm, t, v, w)...
    // ↑ missing: u.X(), u.Y()
    )
}
```

**Attack.** In the GG18 proof system, $u = g^\alpha$ is the commitment to the randomness
used in the response $s_1 = \alpha + e \cdot x$. Omitting it from the hash means the
challenge $e$ is independent of the prover's randomness commitment. An adversary can:

1. Obtain a valid proof $\pi = (z, z', t, v, w, u, s_1, s_2, t_1, t_2)$ for statement
   $(X, c_1, c_2)$ in one session.
2. In a different session with statement $(X', c_1', c_2')$, recompute the challenge $e'$
   using the *new* public values (since $u$ was not committed to) and solve for a forged
   response $s_1' = \alpha' + e' \cdot x$ using a freshly chosen $\alpha'$.
3. The resulting $\pi'$ passes `VerifyMtAwc` against $(X', c_1', c_2')$ even though the
   prover never knew $x'$ satisfying $X' = g^{x'}$.

The finding was filed as [Issue #42](https://github.com/bnb-chain/tss-lib/issues/42)
(*"Malleable ZKProof for Bob in MtAwc"*) from an external audit.

**Remediation.** [PR #43](https://github.com/bnb-chain/tss-lib/pull/43) (merged
September 11, 2019) added `u.X(), u.Y()` to the hash input, binding the challenge to the
full GG18 Fig. 11 statement ([source](https://github.com/bnb-chain/tss-lib/blob/v1.3.5/crypto/mta/proofs.go)):

```go
// FILE: crypto/mta/proofs.go — bnb-chain/tss-lib (fixed, post-PR #43)
// ([source](https://github.com/bnb-chain/tss-lib/blob/v1.3.5/crypto/mta/proofs.go))

if X != nil {
    eHash = common.SHA512_256i(
        append(pk.AsInts(), X.X(), X.Y(), c1, c2, u.X(), u.Y(), z, zPrm, t, v, w)...
    // ↑ u.X(), u.Y() now included — challenge is bound to the commitment
    )
}
```

### Example 3: Range and Factor Proofs Without Session Binding (tss-lib v1.x MtA)

The GG18 range proof (`ProveRangeAlice`, Fig. 9) runs on the *sender's* side of MtA and
proves that Alice's plaintext $m$ lies in a range $[0, q^3)$. In v1.x, the challenge is
computed as:

```go
// FILE: crypto/mta/range_proof.go — bnb-chain/tss-lib v1.3.5 (vulnerable)
// ([source](https://github.com/bnb-chain/tss-lib/blob/v1.3.5/crypto/mta/range_proof.go))

// Challenge binds only to the Paillier key, ciphertext, and Pedersen commitments.
// No session ID — a proof from one MtA call is structurally valid in any other.
eHash := common.SHA512_256i(append(pk.AsInts(), c, z, u, w)...)
e = common.RejectionSample(q, eHash)
```

Because neither the sender's party identity nor any session-specific value appears, a range
proof produced during one signing session is mathematically valid for any other session that
uses the same Paillier key and the same plaintext range. An adversary who records Alice's
proof in session $A$ can replay it in session $B$, convincing Bob that an arbitrarily
crafted ciphertext encrypts a value in range without Alice having generated a fresh proof.

The CGGMP21 **factor proof** (`facproof`) replaces the GG18 range proof with a more
principled construction that proves $N_0 = pq$ with $p, q > 2^{1023}$. From its
introduction in v2.0.0, it takes `Session []byte` as its first argument and includes it in
the Fiat-Shamir hash via `SHA512_256i_TAGGED`:

```go
// FILE: crypto/facproof/proof.go — bnb-chain/tss-lib v2.0.0 (correctly bound)
// ([source](https://github.com/bnb-chain/tss-lib/blob/v2.0.0/crypto/facproof/proof.go))

func NewProof(Session []byte, ec elliptic.Curve, N0, NCap, s, t, N0p, N0q *big.Int) (*ProofFac, error) {
    // ...
    // e binds to Session — this proof is valid only for the current session
    eHash := common.SHA512_256i_TAGGED(Session, N0, NCap, s, t, P, Q, A, B, T, sigma)
    e = common.RejectionSample(q, eHash)
    // ...
}
```

### Commit Timeline

| Date | Repository | Artifact | Description |
|------|-----------|----------|-------------|
| Sep 9, 2019 | [bnb-chain/tss-lib](https://github.com/bnb-chain/tss-lib) | [Issue #42](https://github.com/bnb-chain/tss-lib/issues/42) | Audit finding: `ProofBobWC` Fiat-Shamir hash missing `u = g^α`; challenge not bound to the full proof statement |
| Sep 11, 2019 | [bnb-chain/tss-lib](https://github.com/bnb-chain/tss-lib) | [PR #43](https://github.com/bnb-chain/tss-lib/pull/43) | Fix: add `u.X(), u.Y()` to `ProofBobWC` hash; also fixes the `Verify` path |
| Dec 2022 | — | [CVE-2022-47930](https://nvd.nist.gov/vuln/detail/CVE-2022-47930) | Published: IoFinnet tss-lib before v2.0.0 — `ssid` not used in Schnorr proof or any sub-protocol proof; replay and spoofing of proofs possible |
| Dec 2022 | — | [CVE-2022-47931](https://nvd.nist.gov/vuln/detail/CVE-2022-47931) | Published (CVSS 9.1): IoFinnet tss-lib before v2.0.0 — hash collision in `SHA512_256` allows two different proof statements to produce the same challenge |
| Mar 23, 2023 | — | [Kudelski Security blog](https://research.kudelskisecurity.com/2023/03/23/multiple-cves-in-threshold-cryptography-implementations/) | Public disclosure of CVE-2022-47930 / CVE-2022-47931 and related findings across multiple TSS implementations |
| Aug 23, 2023 | [bnb-chain/tss-lib](https://github.com/bnb-chain/tss-lib) | [PR #256](https://github.com/bnb-chain/tss-lib/pull/256) / [commit `1a14f3ac`](https://github.com/bnb-chain/tss-lib/commit/1a14f3ac9e) | Fix CVE-2022-47930: add `Session []byte` to `ZKProof`, `ZKVProof`, and all CGGMP21 proof types; use `SHA512_256i_TAGGED` throughout |
| Aug 26, 2023 | [bnb-chain/tss-lib](https://github.com/bnb-chain/tss-lib) | v2.0.0 release | All session-binding fixes shipped; incompatible with v1.x proof format; downstream forks must upgrade all nodes simultaneously |

### Real-World Impact

**IoFinnet / Kudelski Security disclosure — \$70B at risk (December 2022).** The
[IoFinnet security disclosure](https://medium.com/@iofinnet/security-disclosure-for-ecdsa-and-eddsa-threshold-signature-schemes-4e969af7155b)
described CVE-2022-47930 and CVE-2022-47931 as affecting all deployments of `tss-lib`
before v2.0.0. IoFinnet and Kudelski Security estimated that over \$70 billion in
cryptoassets were protected by threshold wallets built on the affected library at the time
of disclosure. The replay attack vector (CVE-2022-47930) enables a malicious insider — a
party participating in a legitimate signing ceremony — to authenticate as another party in
a future session, potentially taking unilateral control of the threshold key.

**BNB Chain ecosystem (2019–2023).** `bnb-chain/tss-lib` is the reference implementation
for BNB Chain's custody infrastructure and has been forked or vendored by dozens of
projects including Swingby Skybridge, Keep Network, and multiple cross-chain bridges. The
`ProofBobWC` missing-`u` bug (Issue #42) was present from the library's first public
release until the September 2019 audit. Any signing ceremony run before that fix could
have had its MtA range proofs malleated without detection. tss-lib v1.x (lacking session
binding) remained the deployed version across most downstream forks until at least the
August 2023 v2.0.0 release, a four-year window of exposure.
