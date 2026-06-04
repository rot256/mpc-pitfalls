---
title: "`axelarnetwork/tofnd` accepts spoofed `from` field on the wire"
date: 2021-04-29
primitives: [secure-channel]
repository: https://github.com/axelarnetwork/tofnd
issue: 60
---

Axelar's
tofnd is a Rust daemon implementing [GG20](https://eprint.iacr.org/2020/540)
(Gennaro–Goldfeder, 2020), a threshold-ECDSA protocol widely deployed in MPC wallet
implementations. Each message is wrapped in a `TrafficIn` envelope that carries both a
transport-level sender identity (`from_party_uid`) and an inner `MsgMeta` with a
protocol-level sender index (`from: usize`). As reported in [Issue #60](https://github.com/axelarnetwork/tofnd/issues/60),
the inner `from` field is unauthenticated: a malicious party can edit it in the
binary payload and send messages on behalf of any other party.

The vulnerable handler discarded the transport identity and passed the raw payload
straight to the cryptographic core
([source](https://github.com/axelarnetwork/tofnd/blob/56068f8f6090362a33d948e837f5f3442355ecae/src/gg20/protocol.rs#L106-L117)):

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
field in its public API ([Issue #42](https://github.com/axelarnetwork/tofn/issues/42))
so tofnd could then enforce `from_party_uid == MsgMeta::from` before dispatch.