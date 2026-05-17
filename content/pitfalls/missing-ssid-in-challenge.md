---
title: "Challenge Hash Missing Session Identifier (ssid)"
class: lack-of-context-binding
hidden: true
source: "zk-proofs-not-bound.md"
primitives: [zkp, commitment]
---

### Challenge Hash Missing Session Identifier (ssid)

<!--<div class="pitfall-flags"><span class="flag flag-shared">Shared example with <a href="#challenge-hash-missing-provers-party-identity">Challenge Hash Missing Prover's Party Identity</a></span></div>
-->

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

<!--**Example: CVE-2022-47930 — Schnorr PoK in bnb-chain/tss-lib.** The Schnorr PoK in
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
-->

**Example: Safeheron CMP — LeastAuthority audit Issue C ([PR #12](https://github.com/Safeheron/multi-party-sig-cpp/pull/12), commit [`468af11`](https://github.com/Safeheron/multi-party-sig-cpp/commit/468af11c7c8cf58b314bd893aab5fbb81a996b18)).**
The same omission appeared independently in `Safeheron/multi-party-sig-cpp`, a C++
implementation of the CMP / CGGMP21 threshold-ECDSA protocol. LeastAuthority's audit
flagged it explicitly as **"Issue C: Used Session Identifier correctly"**, alongside
**"Issue A: Weak Fiat-Shamir Transformation Implemented in Various NIZKs"** and a
suggestion to **"Write the Salt at the Beginning of Each Fiat-Shamir Transcript"**. The
remediation, merged October 27 2023 across 73 files, introduced
`mpc_flow::common::SIDMaker` to derive a session identifier consistently across every
CMP proof, then prepended it to each FS transcript through a re-organised `util::*`
hash-input ordering ([source](https://github.com/Safeheron/multi-party-sig-cpp/blob/468af11c7c8cf58b314bd893aab5fbb81a996b18/src/multi-party-ecdsa/cmp/minimal_key_gen/round2.cpp)):

```cpp
// src/multi-party-ecdsa/cmp/minimal_key_gen/round2.cpp — Safeheron (fixed, post-468af11)
#include "mpc-flow/common/sid_maker.h"
using safeheron::mpc_flow::common::SIDMaker;
// SIDMaker constructs the per-session identifier from the participant set + protocol
// context; that identifier feeds every subsequent FS challenge in keygen, refresh,
// and signing rounds.
```

LeastAuthority confirmed the remediation, and the fix landed in v1.0 of the library.
This is the same root cause as CVE-2022-47930 (FS transcript not bound to the protocol
session) reproducing in an independent codebase audited by an independent firm —
evidence that the pattern recurs across MPC implementations and that fixing it requires
a deliberate, library-wide salt/SID convention rather than a single-proof patch.

**Example: bronlabs/bron-crypto — sessionId promoted to mandatory commitment input ([commit `6e35b35`](https://github.com/bronlabs/bron-crypto/commit/6e35b35a77e092501c020554a93b1d35030b43a8), PR #183, December 14 2023).**
A third instance of the pattern appears in `bronlabs/bron-crypto`, a Go MPC library
implementing Lindell17, DKLs23, and Lindell22 threshold-signature protocols. The
pre-fix `commitments.Commit(message)` API took only the value being committed, with no
session input; the patch reorganised the API so that every callsite must supply a
non-empty `sessionId` ahead of the message
([source](https://github.com/bronlabs/bron-crypto/blob/6e35b35a77e092501c020554a93b1d35030b43a8/pkg/commitments/commitments.go#L40-L57)):

```go
// pkg/commitments/commitments.go — bronlabs/bron-crypto (post-fix)
func Commit(sessionId []byte, message ...[]byte) (Commitment, Witness, error) {
    if len(sessionId) == 0 {
        return nil, nil, errs.NewInvalidArgument("sessionId is empty/nil")
    }
    messageWithSessionId := append(append([][]byte{}, sessionId), message...)
    return CommitWithoutSession(messageWithSessionId...)
}

func Open(sessionId []byte, commitment Commitment, witness Witness, message ...[]byte) error {
    messageWithSessionId := append(append([][]byte{}, sessionId), message...)
    return OpenWithoutSession(commitment, witness, messageWithSessionId...)
}
```

The old session-less primitive is renamed `CommitWithoutSession` / `OpenWithoutSession`
and confined to test code. The change rippled through every MPC protocol shipped in the
library — Paillier LPDL and range-proof rounds, agree-on-random, PRZS setup, DKLs23
signing, Lindell17 DKG and signing, Lindell22 interactive- and non-interactive-Schnorr
signing — each of which now threads `sessionId` as the first argument of every commit /
open / proof round. The diff structure (rename + non-empty guard at the choke point)
is the same defence-in-depth pattern that Safeheron's `SIDMaker` provides at the
hash-input level: make session-binding the only callable path.
