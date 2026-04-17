---
title: "Zero Knowledge Proofs Not Bound to the Protocol Execution"
class: "Protocol"
order: 3
---

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
individual proof messages. For *intrinsic* Fiat-Shamir failures (omitted statement,
omitted commitment, or insufficient soundness), see the [Fiat-Shamir](../fiat-shamir/)
pitfall.

### Example: Schnorr Proof of Knowledge Without Session Binding (CVE-2022-47930)

The Schnorr PoK in `bnb-chain/tss-lib` lets party $P_i$ prove knowledge of its secret key
share $x_i$ by sending $(R = g^k, s = k + c \cdot x_i)$ where $c$ is a Fiat-Shamir
challenge. In v1.x the challenge is derived solely from the public key
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
2023) added a `Session []byte` parameter that is prepended to every proof challenge via
the domain-separating `SHA512_256i_TAGGED` ([source](https://github.com/bnb-chain/tss-lib/blob/v2.0.0/crypto/schnorr/schnorr_proof.go)):

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

The same fix was applied to `ZKVProof` (the companion proof in the same file) and to
every CGGMP21 proof type shipped in v2.0.0: `facproof` (the replacement for the GG18
range proof in `crypto/mta/range_proof.go`), `modproof`, and `mta/proofs.go`. Each of
these now accepts `Session []byte` as its first argument and hashes it via
`SHA512_256i_TAGGED`. The range proof is worth calling out: in v1.x it bound only to the
Paillier key and the ciphertext, so a proof generated in one signing session was
structurally valid in any other using the same key. CGGMP21's `facproof` is designed with
session binding from the start.

### Commit Timeline

| Date | Repository | Artifact | Description |
|------|-----------|----------|-------------|
| Jun 18, 2019 | [bnb-chain/tss-lib](https://github.com/bnb-chain/tss-lib) | [commit `c8535ddd`](https://github.com/bnb-chain/tss-lib/commit/c8535dddd7) | Initial commit of `crypto/schnorr/schnorr_proof.go`: `NewSchnorrProof` / `Verify` introduced with no session, context, or party binding. This is the original form of CVE-2022-47930. |
| Dec 2022 | — | [CVE-2022-47930](https://nvd.nist.gov/vuln/detail/CVE-2022-47930) | Published: IoFinnet tss-lib before v2.0.0. `ssid` not used in Schnorr proof or any sub-protocol proof; replay and spoofing of proofs possible. |
| Dec 2022 | — | [CVE-2022-47931](https://nvd.nist.gov/vuln/detail/CVE-2022-47931) | Published (CVSS 9.1): IoFinnet tss-lib before v2.0.0. Hash collision in `SHA512_256` allows two different proof statements to produce the same challenge. |
| Mar 23, 2023 | — | [Kudelski Security blog](https://research.kudelskisecurity.com/2023/03/23/multiple-cves-in-threshold-cryptography-implementations/) | Public disclosure of CVE-2022-47930 / CVE-2022-47931 and related findings across multiple TSS implementations. |
| Aug 23, 2023 | [bnb-chain/tss-lib](https://github.com/bnb-chain/tss-lib) | [PR #256](https://github.com/bnb-chain/tss-lib/pull/256) / [commit `1a14f3ac`](https://github.com/bnb-chain/tss-lib/commit/1a14f3ac9e) | Fix CVE-2022-47930: add `Session []byte` to `ZKProof`, `ZKVProof`, and all CGGMP21 proof types; use `SHA512_256i_TAGGED` throughout. |
| Aug 26, 2023 | [bnb-chain/tss-lib](https://github.com/bnb-chain/tss-lib) | v2.0.0 release | All session-binding fixes shipped; incompatible with v1.x proof format; downstream forks must upgrade all nodes simultaneously. |

Two things stand out in this timeline. First, the bug was not a regression: the very
first commit of `crypto/schnorr/schnorr_proof.go`
([`c8535ddd`](https://github.com/bnb-chain/tss-lib/commit/c8535dddd7), June 18, 2019)
introduced `NewSchnorrProof` with no session, context, or party binding. That is the
exact construction later published as CVE-2022-47930. The vulnerable code sat unchanged
in production for more than four years, during which the library became the reference
threshold-ECDSA implementation for the BNB Chain ecosystem. Independent rediscovery by
IoFinnet and Kudelski Security in late 2022 forced the issue into public view.

Second, even after disclosure, the fix took eight months to land (PR #256, August 23,
2023) and required a *breaking* change to the proof format: adding `Session []byte` to
the Fiat-Shamir hash changes every challenge value, so v2.0.0 proofs are not verifiable
by v1.x code and vice versa. For a threshold wallet, this means every participating node
has to upgrade simultaneously. There is no gradual rollout, because a single v1.x node
in the signing set will reject every v2.0.0 proof. That coordination cost, not the patch
itself, is the hard part of remediating a missing-session-binding bug after the fact, and
it is the main reason v1.x deployments persisted in downstream forks long after the CVE
was public.

### Real-World Impact

**IoFinnet / Kudelski Security disclosure (\$70B at risk, December 2022).** The
[IoFinnet security disclosure](https://medium.com/@iofinnet/security-disclosure-for-ecdsa-and-eddsa-threshold-signature-schemes-4e969af7155b)
described CVE-2022-47930 and CVE-2022-47931 as affecting all deployments of `tss-lib`
before v2.0.0. IoFinnet and Kudelski Security estimated that over \$70 billion in
cryptoassets were protected by threshold wallets built on the affected library at the time
of disclosure. The replay attack vector (CVE-2022-47930) enables a malicious insider (a
party participating in a legitimate signing ceremony) to authenticate as another party in
a future session, potentially taking unilateral control of the threshold key.

**BNB Chain ecosystem (2019–2023).** `bnb-chain/tss-lib` is the reference implementation
for BNB Chain's custody infrastructure and has been forked or vendored by dozens of
projects including Swingby Skybridge, Keep Network, and multiple cross-chain bridges.
tss-lib v1.x (lacking session binding) remained the deployed version across most downstream
forks until the August 2023 v2.0.0 release, a four-year window of exposure.
