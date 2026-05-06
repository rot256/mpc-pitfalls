---
title: "Unauthenticated or unencrypted point-to-point channels"
class: "Insecure Subprotocol Instantiation"
source: "uc-protocols.md"
---

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
