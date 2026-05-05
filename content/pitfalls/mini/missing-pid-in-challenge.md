---
title: "Challenge hash missing prover's party identity"
class: "Lack of Binding to Execution Context"
source: "zk-proofs-not-bound.md"
---

### Challenge hash missing prover's party identity

<!--<div class="pitfall-flags"><span class="flag flag-shared">Shared example with <a href="#challenge-hash-missing-session-identifier-ssid">Challenge hash missing session identifier (ssid)</a></span></div>
-->

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

<!--**Example.** CVE-2022-47930 (above) covers this as well: the vulnerable Schnorr
challenge hash omitted *both* the session identifier and the prover's party identity,
and the published attack exploits both gaps simultaneously (the adversary replays $P_i$'s
proof as $P_m$'s contribution in a new session). The v2.0.0 fix's `Session []byte` is
typically derived to include the participant set for the current run, closing both the
session-level and party-level replay vectors. No distinct CVE has been assigned to a
"party identity only" variant — in every observed real-world case the `ssid` and party
identity are missing together.-->

<!--
