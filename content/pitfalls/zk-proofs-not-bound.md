---
title: "Zero Knowledge Proofs Not Bound to the Protocol Execution"
class: "Fiat-Shamir & ZK Proofs"
order: 5
---

### Challenge hash missing session identifier (ssid)

<div class="pitfall-flags"><span class="flag flag-shared">Shared example with <a href="#challenge-hash-missing-provers-party-identity">Challenge hash missing prover's party identity</a></span></div>

**What can go wrong.** A Fiat-Shamir challenge hash that does not include a session
identifier (`ssid`) produces the same challenge value across every run of the same
statement. Two invocations of the proof — one in key-generation session $A$, another in
signing session $B$ — differ only in the surrounding protocol context, which the hash
does not see. The proof bytes from session $A$ therefore remain structurally valid in
session $B$.

**Security implication.** An adversary who observes a legitimate proof $\pi$ generated
by an honest party in session $A$ replays $\pi$ in any later session $B$ that reuses
the same public statement. The verifier accepts the replay because the recomputed
challenge matches. In threshold-signature keygen this lets a corrupt party skip its
proof-of-knowledge obligation in future ceremonies by reusing an earlier honest proof;
in signing rounds it enables unauthorised progress with a replayed round message.

**How to avoid.** Derive a session identifier `ssid` from every public parameter of the
current run — participant set, group public key, round counters, any caller-supplied
nonce — and prepend it to every FS challenge hash via a domain-separating tagged-hash
construction (for example `SHA512_256i_TAGGED(ssid, …)`). A proof from a different
session then produces a different challenge and fails verification on replay.

**Example: CVE-2022-47930 — Schnorr PoK in bnb-chain/tss-lib.** The Schnorr PoK in
`bnb-chain/tss-lib` lets party $P_i$ prove knowledge of its secret key share $x_i$ by
sending $(R = g^k, s = k + c \cdot x_i)$ where $c$ is a Fiat-Shamir challenge. In v1.x
the challenge was derived solely from the public key and the commitment
([source](https://github.com/bnb-chain/tss-lib/blob/v1.3.5/crypto/schnorr/schnorr_proof.go#L30-L51)):

```go
// FILE: crypto/schnorr/schnorr_proof.go — bnb-chain/tss-lib v1.3.5 (vulnerable)

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

The NVD description of [CVE-2022-47930](https://nvd.nist.gov/vuln/detail/CVE-2022-47930)
states: *"the Schnorr proof of knowledge … does not utilize a session id, context, or
random nonce in the generation of the challenge. This could allow a malicious user or an
eavesdropper to replay a valid proof sent in the past."* The fix
([PR #256](https://github.com/bnb-chain/tss-lib/pull/256), commit
[`1a14f3ac`](https://github.com/bnb-chain/tss-lib/commit/1a14f3ac9e), merged August 23,
2023) added a `Session []byte` parameter prepended to every proof challenge via the
domain-separating `SHA512_256i_TAGGED`:

```go
// FILE: crypto/schnorr/schnorr_proof.go — bnb-chain/tss-lib v2.0.0 (fixed)

func NewZKProof(Session []byte, x *big.Int, X *crypto.ECPoint) (*ZKProof, error) {
    // ...
    cHash := common.SHA512_256i_TAGGED(Session, X.X(), X.Y(), g.X(), g.Y(), alpha.X(), alpha.Y())
    c := common.RejectionSample(q, cHash)
    // ...
}
```

The same fix was applied to `ZKVProof` (the companion proof in the same file) and to
every CGGMP21 proof type shipped in v2.0.0 (`facproof`, `modproof`, `mta/proofs.go`),
each of which now accepts `Session []byte` as its first argument.

### Challenge hash missing prover's party identity

<div class="pitfall-flags"><span class="flag flag-shared">Shared example with <a href="#challenge-hash-missing-session-identifier-ssid">Challenge hash missing session identifier (ssid)</a></span></div>

**What can go wrong.** A Fiat-Shamir challenge hash that does not include the prover's
party identifier (`pid`) produces the same challenge for any party claiming to prove the
same public statement. Two provers — honest $P_i$ and corrupt $P_m$ — computing the FS
hash on identical public inputs obtain identical challenges. A proof $\pi_i$ produced
honestly by $P_i$ can be replayed verbatim by $P_m$, who then claims to have known the
underlying witness despite never having seen it.

**Security implication.** In threshold-signature keygen, a corrupt party $P_m$ that
arranges (through rogue-key setup) to present the same public-key share $X_m = X_i$ as
an honest $P_i$ records $P_i$'s Schnorr proof and submits it as its own round
contribution, passing the proof-of-knowledge check without holding any secret. This is
the classical rogue-key attack executed at the Fiat-Shamir layer: $P_m$ claims to have
contributed to the shared key without knowing the matching share.

**How to avoid.** Include the prover's party identifier (`pid`, public key, or
protocol-assigned role) in every FS challenge hash, in addition to the session
identifier. A proof computed by $P_i$ then produces a different challenge when replayed
under $P_m$'s identity and fails verification. In practice many libraries fold the party
identifier into the `ssid` derivation (the participant set is included in `ssid`), which
closes this variant as a side-effect of the session-binding fix.

**Example.** CVE-2022-47930 (above) covers this as well: the vulnerable Schnorr
challenge hash omitted *both* the session identifier and the prover's party identity,
and the published attack exploits both gaps simultaneously (the adversary replays $P_i$'s
proof as $P_m$'s contribution in a new session). The v2.0.0 fix's `Session []byte` is
typically derived to include the participant set for the current run, closing both the
session-level and party-level replay vectors. No distinct CVE has been assigned to a
"party identity only" variant — in every observed real-world case the `ssid` and party
identity are missing together.

<!--
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
-->
