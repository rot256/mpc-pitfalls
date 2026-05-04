---
title: "UC Setup Assumptions Not Realized in Implementation"
class: "UC Setup Assumptions Not Realized"
order: 6
---

The [**Universal Composability (UC)** framework](https://eprint.iacr.org/2000/067)
(Canetti, FOCS 2001) gives MPC protocols the strongest security guarantee available: a
UC-secure protocol behaves like an incorruptible ideal
functionality regardless of what else runs concurrently alongside it. But UC security is
not a property of the cryptographic core alone — it extends to the communication
infrastructure and to how session and party identifiers are managed. A protocol proven
UC-secure under ideal channels provides *no guarantee* when those channels are replaced
by unauthenticated sockets, unenforced broadcast flags, or unverified session identifiers.
The mini-pitfalls below cover the most common implementation-layer failures that break
the UC assumptions a protocol proof relied on.

### Multicast masquerading as broadcast

**What can go wrong.** UC proofs of MPC protocols are written against idealized
communication channels, in particular a *reliable broadcast* channel in which every
honest party receives the same message from the sender in a given round. A library
that cannot tell whether a given round was supposed to be broadcast or point-to-point
cannot enforce that assumption. If the application instantiates "broadcast" as a loop
of per-peer sends, a malicious sender can equivocate (send $v_1$ to one honest party
and $v_2$ to another) and no honest participant can detect the split. Echo-broadcast —
every party re-broadcasts what it received before accepting — provides only
single-round local consistency, not full Byzantine agreement, so a malicious sender
can shift the split into the second round.

**Security implication.** Honest parties end up with different views of the same
protocol round. The composition-level guarantee the UC proof relied on (that the round
fixed a single value across all honest views) no longer holds, and subsequent rounds
run on diverging state. In threshold signing the practical consequences include
key-generation concluding with honest parties disagreeing on the public key, silent
denial-of-service by a single adversary, and — depending on which round is attacked —
share exposure, proof forgeries, or permanently-inconsistent key material.

**How to avoid.** Implement a reliable broadcast protocol (not just echo-broadcast) for
any round whose security proof requires Byzantine agreement. In settings with fewer than
$n/3$ corruptions, Bracha broadcast provides the required guarantees. Enforce the
per-round broadcast-vs-P2P classification at the library boundary using the protocol
specification as reference, rather than delegating the decision to the caller.

**Example: tss-lib `ParseWireMessage`.** The library's sole entry-point for inbound
messages delegates the broadcast/P2P decision entirely to the application layer
([source](https://github.com/bnb-chain/tss-lib/blob/master/tss/wire.go)):

```go
// FILE: tss/wire.go — bnb-chain/tss-lib (all versions)

func ParseWireMessage(wireBytes []byte, from *PartyID, isBroadcast bool) (ParsedMessage, error) {
    wire := new(MessageWrapper)
    wire.IsBroadcast = isBroadcast  // set by caller — library never validates this
    // ...
}
```

The library never cross-checks whether the round that generated `wireBytes` is
specified by the protocol to be a broadcast or a P2P round. Two failure modes feed off
this. *Sender equivocation*: a malicious sender $P_m$ sends $v_1$ to one honest party
and $v_2$ to another during a round whose security proof assumed reliable broadcast; if
the application instantiated "broadcast" as a loop of P2P sends, nothing catches the
inconsistency. *Classification mismatch*: two honest receivers whose transport layers
classify the same wire bytes differently end up with diverging protocol state — one
treats a value as globally agreed upon, the other as a personal P2P message.

Downstream projects including [THORChain TSS](https://github.com/thorchain/tss),
[Swingby Skybridge](https://github.com/SwingbyProtocol/tss-lib), and
[Keep Network](https://github.com/keep-network/keep-core) all deployed `tss-lib` without
implementing a reliable broadcast layer, inheriting this exposure. The library itself
has not changed this API as of v2.0.0: `tss/wire.go` is unchanged since August 2021 and
no reliable-broadcast implementation exists in the tree.

### Unauthenticated or unencrypted point-to-point channels

**What can go wrong.** UC proofs of MPC protocols typically assume authenticated, and
usually confidential, channels between every pair of parties. Implementations that
hand-roll the transport layer — raw TCP, ad-hoc JSON over HTTP, implicit trust in a
central coordinator that re-signs messages — routinely fail to realize these
assumptions. The protocol proof assumes the channel prevents network-layer
impersonation and eavesdropping; the deployed transport does not.

**Security implication.** Without per-message authentication, a network attacker can
impersonate parties and inject messages honest parties attribute to the wrong source;
the victim of the attribution is then blamed for protocol violations it did not commit.
Without confidentiality, intermediate values that the ideal functionality hides leak to
the network, and downstream secret-dependent computations become vulnerable to offline
analysis. In threshold signing this translates to rogue messages causing spurious
aborts, silent share exposure, and key-extraction attacks that exploit observed
intermediate values.

**How to avoid.** Instantiate the point-to-point channels with mutual TLS between each
pair of parties, keyed to the specific participant set for this protocol run
(certificate pinning at minimum; ideally session-scoped keys derived from a higher-level
authenticated key-exchange). Never run the cryptographic protocol over unauthenticated
transport, even "for testing" — integration-test wiring often migrates into production
unnoticed.

**Example: `coinbase/kryptology` GG20 DKG ships secret shares unencrypted.** GG20's
key-generation proof assumes the Round 2 P2P delivery of each Shamir share $x_{ij}$
runs over a confidential channel — the original paper instantiates this with Paillier
encryption keyed to the recipient. The Coinbase library's GG20 implementation drops the
encryption step and returns the share as a bare struct field
([source](https://github.com/coinbase/kryptology/blob/master/pkg/tecdsa/gg20/participant/dkg_round2.go)):

```go
// FILE: pkg/tecdsa/gg20/participant/dkg_round2.go — coinbase/kryptology

type DkgRound2P2PSend struct {
    xij *v1.ShamirShare  // raw share — no Paillier encryption applied
}
// ...
p2PSend[id] = &DkgRound2P2PSend{ xij: dp.state.X[id-1] }
```

An integrator filed [issue #29](https://github.com/coinbase/kryptology/issues/29) after
having to fork the library to make `xij` exportable for transmission, noting it "feels
unsafe to share in unencrypted form" and pointing out that Swingby's tss-lib fork
[Paillier-encrypts the share](https://github.com/SwingbyProtocol/tss-lib/blob/668d0061fadf08bf2ba9f7e9287516fc173b6b9c/ecdsa/keygen/round_3.go#L127-L133)
at the equivalent round. The maintainer confirmed in the same thread: *"You should
encrypt everything sent between participants since the paper states it's only secure in
the presence of a secure channel."* The library nonetheless leaves channel
confidentiality entirely to the application — any deployment that wires
`DkgRound2P2PSend` over a non-confidential transport loses Round 2 secret shares to a
network observer, which is sufficient to reconstruct the long-term ECDSA private key
once $t$ such observations accumulate.

**Example: `axelarnetwork/tofnd` accepts spoofed `from` field on the wire.** Axelar's
GG20 daemon (a separate Rust implementation, not tss-lib) wraps each protocol message
in a `TrafficIn` envelope that carries the transport-level sender identity
(`from_party_uid`) alongside an inner `MsgMeta` that carries the protocol-level sender
index (`from: usize`). [Issue #60](https://github.com/axelarnetwork/tofnd/issues/60),
filed by maintainer Gus Gutoski in April 2021, describes the failure directly:

> *Currently, the sender of a tofnd message is not authenticated. Thus, malicious
> parties could spoof messages from other parties. […] It is easy for a malicious actor
> to dig into the binary payload and spoof this `from` field and therefore send messages
> on behalf of other parties.*

The vulnerable handler discarded the transport identity and passed the raw payload
straight to the cryptographic core
([`src/gg20/protocol.rs#L106-L117`](https://github.com/axelarnetwork/tofnd/blob/56068f8f6090362a33d948e837f5f3442355ecae/src/gg20/protocol.rs#L106-L117)):

```rust
// FILE: src/gg20/protocol.rs — axelarnetwork/tofnd (pre-fix)

// The transport-level from_party_uid in TrafficIn was ignored;
// only the binary payload was forwarded to tofn for deserialization.
// tofn then trusted the inner MsgMeta { from: usize, ... } self-attribution.
```

A malicious party Alice with subshares `{0, 1}` could craft a message with
`MsgMeta::from = 2` (Bob's subshare index), and no consistency check linked that index
back to the transport-authenticated `from_party_uid`. The remediation
([tofn #42](https://github.com/axelarnetwork/tofn/issues/42)) required exposing the
`from` field in tofn's public API so tofnd could enforce
`from_party_uid == MsgMeta::from` before dispatch. The sister-issue thread is explicit
about which failure mode each spoof produces: cross-party spoof surfaces as an
authentication fault, intra-party subshare spoof surfaces as a ZK-proof failure — both
were silently accepted before the fix.

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
### Commit Timeline

| Date | Repository | Artifact | Description |
|------|-----------|----------|-------------|
| Oct 22, 2019 | [bnb-chain/tss-lib](https://github.com/bnb-chain/tss-lib) | [commit `c6f567443e`](https://github.com/bnb-chain/tss-lib/commit/c6f567443e) | `ParseWireMessage` introduced with caller-controlled `isBroadcast` parameter, as part of a protobuf-wrapper refactor for mobile messaging; no library-level enforcement of broadcast vs P2P rounds. Still unchanged as of v2.0.0. |
| ~2022 | [IoFinnet/threshlib](https://github.com/IoFinnet/threshlib) | Kudelski Security audit (KS-IOF-F-02) | Hash collision in `SHA512_256`: missing per-input length prefix allows two different input tuples to produce the same hash |
| ~2022 | [IoFinnet/threshlib](https://github.com/IoFinnet/threshlib) | [commit `369ec50`](https://github.com/IoFinnet/threshlib/commit/369ec50be1437588a9733443bcb2f15b794601d4) | Fix KS-IOF-F-02: add 8-byte length tag after each delimiter in `SHA512_256` and `SHA512_256i` |
| Mar 24, 2023 | [bnb-chain/tss-lib](https://github.com/bnb-chain/tss-lib) | [PR #233](https://github.com/bnb-chain/tss-lib/pull/233) | Fix hash collision: import IoFinnet KS-IOF-F-02 fix into `common/hash.go` |

Two things stand out in this timeline. First, the broadcast-flag design is not a
regression. `ParseWireMessage` was introduced on October 22, 2019
([commit `c6f567443e`](https://github.com/bnb-chain/tss-lib/commit/c6f567443e)) with
`isBroadcast` already delegated entirely to the caller, as part of a protobuf-wrapper
refactor for mobile messaging. The API has not changed since. Every downstream deployment
over the past six-plus years (THORChain, Swingby, Keep Network, IoFinnet's `threshlib`)
has inherited the same caller-controlled flag.

Second, unlike the hash-collision bug (now covered on the Hash Functions page), which
was fixed once it was publicly disclosed (via Kudelski's KS-IOF-F-02 audit and the
corresponding fix in PR #233), the broadcast-flag issue has resisted a library-level
fix by design. Enforcing broadcast semantics inside tss-lib would require the library
to ship a reliable-broadcast implementation, which carries round-complexity and
liveness costs and forces an opinion on the application's network model. The
maintainers' position has been that the transport layer is the application's
responsibility. Defensible in theory, but in practice every major downstream deployment
has shipped without a real reliable-broadcast layer, so the bug is still openly
present.

-->
