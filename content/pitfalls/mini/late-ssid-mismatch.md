---
title: "Session-ID disagreement not detected early"
class: "Concurrency and Session Lifecycle"
source: "uc-protocols.md"
---

### Session-ID disagreement not detected early

**What can go wrong.** When two honest parties run a shared sub-protocol (OT extension,
MAC check, DLN proof) using a session identifier (`ssid`) that disagrees between them —
because of a bug in ssid derivation, a clock skew, a protocol version mismatch, or a
subtle string-encoding difference — the sub-protocol's consistency check fails. The
failure looks identical from each party's perspective to an actual attack by a malicious
peer: neither party can tell that the cause was a configuration mismatch rather than a
cheating peer.

**Security implication.** In protocols with identifiable abort, each party concludes
the peer is malicious and may permanently blacklist them; a single ssid-derivation bug
can cause honest parties to ban each other. In retry-on-abort protocols, each retry
consumes additional preprocessed randomness; enough retries exhaust a precomputed OT
extension pool, forcing an expensive re-setup. The underlying protocol never completes
while looking, from the inside, exactly like it is under attack.

**How to avoid.** Define session-identifier derivation as a well-specified,
version-tagged function of public protocol inputs (participant set, epoch, caller-supplied
nonce). Detect mismatches at the earliest possible moment — ideally in a dedicated
handshake before any cryptographic sub-protocol runs — and when a consistency check
fails include a diagnostic code that distinguishes "mismatched ssid" from "MAC or
transcript inconsistent under a shared ssid" so operators can tell configuration errors
apart from attacks.

**Example: BitGo `sdk-lib-mpc` DKLS retrofit hardcoded `final_session_id` to zeros.**
BitGo's institutional MPC SDK wraps Silence Laboratories' DKLS WASM bindings to perform
threshold-ECDSA key generation. The DKLS protocol uses `final_session_id` (a 32-byte
value supplied at retrofit time) to bind the OT-extension transcript to a specific
keygen session — without uniqueness here, the OT-setup transcript is constant across
sessions and the protocol's session-isolation guarantee collapses. The retrofit code
path in `modules/sdk-lib-mpc/src/tss/ecdsa-dkls/dkg.ts` shipped with the value
hardcoded to all zeros, so every retrofit wallet across the entire deployment shared
the same `ssid`. The fix landed in [PR #8496](https://github.com/BitGo/BitGoJS/pull/8496)
(merged April 14 2026, internal ticket WAL-392):

```ts
// FILE: modules/sdk-lib-mpc/src/tss/ecdsa-dkls/dkg.ts — BitGo/BitGoJS

// pre-fix — every retrofit wallet on the server shared this ssid
final_session_id: Array(32).fill(0),

// fix — bind the ssid to wallet-specific public material
final_session_id: Array.from(
    createHash('sha256')
        .update(Buffer.from(this.retrofitData.xShare.y, 'hex'))           // pubkey
        .update(Buffer.from(this.retrofitData.xShare.chaincode, 'hex'))   // chaincode
        .digest()
),
```

The PR description spells out the protocol-level impact: *"This weakens DKLS protocol
transcript binding and could allow cross-session confusion when multiple retrofit
wallets sign simultaneously on the same server."* This is the pitfall in its purest
form. The bug was invisible from inside the protocol — no consistency check fires for
"my `ssid` matches my neighbour's `ssid`, but they're both the wrong constant" — and
nothing in the type system prevented the placeholder zero-array from reaching
production. Detection required reasoning about the DKLS spec rather than reading the
code.

**Example: tss-lib `ssid` semantics are unspecified, leaving each integrator to invent
their own.** The library's README instructs callers to "wrap each message with a session
ID" but does not specify the derivation, the wire format, or which sub-protocol
identifiers must agree. [Issue #292](https://github.com/bnb-chain/tss-lib/issues/292) is
the textbook misconfiguration question, asked with no maintainer reply on file:

> *"Does that mean adding additional session id data to a message like below?
> `{ sessionId: out-of-band-id, msg: round-message }`. Or would it be ok to just using
> https for communication and its session id?"*

The two interpretations the integrator floats — application-supplied out-of-band ID vs.
HTTPS session ID — produce mutually unintelligible deployments: two parties built by
different teams will derive `ssid` differently and their consistency checks will fail
with no diagnostic distinguishing "configuration mismatch" from "cheating peer". This is
not hypothetical: [issue #228 ("Keygen Freezing and Session ID Problem")](https://github.com/bnb-chain/tss-lib/issues/228)
is a downstream report of exactly that — random keygen freezes traced by the integrator
back to lacking any way to "[map] session ID to a single run of keygen round." The
library exposes no exported method to read the round of an inbound message, so the
ssid-to-round binding the proof assumes cannot be enforced from outside.

<!--
