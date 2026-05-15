---
title: "Unauthenticated or Unencrypted Point-to-Point Channels"
class: insecure-subprotocol-instantiation
source: "uc-protocols.md"
primitives: [secure-channel, paillier, homomorphic-encryption]
---

### Unauthenticated or Unencrypted Point-to-Point Channels

**What can go wrong.** Many MPC protocol proofs are written in the
*Universal Composability* (UC) framework of
[Canetti (2001)](https://eprint.iacr.org/2000/067), which models the network as ideal
functionalities: typically $\mathcal{F}_{\text{AUTH}}$ for *authenticated* channels
(the recipient is guaranteed to learn the true sender) and $\mathcal{F}_{\text{SMT}}$
for *secure message transmission* (also confidential). When a protocol's proof
assumes such a functionality between every pair of parties, such as in the
threshold-ECDSA protocols [GG18](https://eprint.iacr.org/2019/114) and
[GG20](https://eprint.iacr.org/2020/540), both of which explicitly require
authenticated and (for several rounds) confidential point-to-point channels, the
deployment must operationally realize that assumption, typically through mutual TLS,
signed/encrypted application-level messages, or a noise-protocol handshake.
Implementations that hand-roll the transport layer (raw TCP, ad-hoc JSON over HTTP,
implicit trust in a central coordinator that re-signs messages) routinely fail to
realize these assumptions. The protocol proof assumes the channel prevents
network-layer impersonation and eavesdropping; the deployed transport does not.

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
transport, even "for testing", since integration-test wiring often migrates into production
unnoticed.

**Example: `axelarnetwork/tofnd` accepts spoofed `from` field on the wire.** Axelar's
tofnd is a Rust daemon implementing [GG20](https://eprint.iacr.org/2020/540)
(Gennaro–Goldfeder, 2020), a threshold-ECDSA protocol widely deployed in MPC wallet
implementations. It wraps each protocol message in a `TrafficIn` envelope that
carries the transport-level sender identity (`from_party_uid`) alongside an inner
`MsgMeta` that carries the protocol-level sender index (`from: usize`). [Issue #60](https://github.com/axelarnetwork/tofnd/issues/60) describes the failure directly:

> *Currently, the sender of a tofnd message is not authenticated. Thus, malicious
> parties could spoof messages from other parties. […] It is easy for a malicious actor
> to dig into the binary payload and spoof this `from` field and therefore send messages
> on behalf of other parties.*

The vulnerable handler discarded the transport identity and passed the raw payload
straight to the cryptographic core
([`src/gg20/protocol.rs#L106-L117`](https://github.com/axelarnetwork/tofnd/blob/56068f8f6090362a33d948e837f5f3442355ecae/src/gg20/protocol.rs#L106-L117)):

```rust
// FILE: src/gg20/protocol.rs — axelarnetwork/tofnd (pre-fix, lines 106–117)
while protocol.expecting_more_msgs_this_round() {
    let traffic = chan.receiver.next().await.ok_or(...)?;
    let traffic = traffic.unwrap();
    // Only `traffic.payload` is forwarded to tofn; the transport-level
    // `traffic.from_party_uid` is discarded. tofn then trusts the inner
    // `MsgMeta { from: usize, ... }` self-attribution.
    protocol.set_msg_in(&traffic.payload)?;
}
```

A malicious party Alice with subshares `{0, 1}` could craft a message with
`MsgMeta::from = 2` (Bob's subshare index), and no consistency check linked that index
back to the transport-authenticated `from_party_uid`. The fix is split across two
repos: tofn (the cryptographic library tofnd wraps) had to first expose the `from`
field in its public API ([tofn #42](https://github.com/axelarnetwork/tofn/issues/42))
so tofnd could then enforce `from_party_uid == MsgMeta::from` before dispatch.

**Example: `coinbase/kryptology` GG20 DKG ships secret shares unencrypted.** GG20's
joint key-generation procedure (inherited from
[GG18](https://eprint.iacr.org/2019/114)) assumes the Round 2 P2P delivery of each
Shamir share $x_{ij}$ runs over a confidential channel, instantiated in the GG18 paper
with Paillier encryption keyed to the recipient.
The Coinbase library's GG20 implementation drops the encryption step and returns the
share as a bare struct field
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
confidentiality entirely to the application. Note that the kryptology repository has since been
[archived by Coinbase](https://github.com/coinbase/kryptology), with an explicit
notice that the library *"should not be used"* and is not used by Coinbase itself.
