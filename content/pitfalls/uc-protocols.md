---
title: "UC Setup Assumptions Not Realized in Implementation"
class: "Protocol"
order: 5
---

The **Universal Composability (UC)** framework [Can01] gives the strongest security guarantee
available for MPC protocols: a UC-secure protocol behaves like an incorruptible ideal
functionality regardless of what else runs concurrently alongside it. But UC security is not
a property of the cryptographic core alone. It extends to the communication infrastructure.
A protocol proven UC-secure under ideal channels provides *no security guarantee* when those
channels are replaced by unauthenticated sockets, unenforced broadcast flags, or
session-unbound proofs. Four categories of implementation failure recur across real
deployments:

1. **Ambiguous hash encoding.** When the domain-separation hash used for Fiat-Shamir
   challenges does not encode input lengths, two structurally different inputs can produce
   the same hash value. An adversary can exploit this to substitute a proof generated for
   one session or statement into a different one. See the
   [Hash Functions](../hash-functions/) pitfall for the full treatment; a brief summary of
   the tss-lib / IoFinnet `threshlib` incident appears under "Further example" below.

2. **Missing session identifiers.** CGGMP21 and other modern threshold ECDSA protocols
   mandate that every sub-protocol ZK proof include a session sub-ID (`ssid`) in its
   Fiat-Shamir hash. Without it, a valid proof from session $A$ is indistinguishable from a
   valid proof for session $B$, enabling cross-session replay attacks. A related but
   distinct failure mode is `ssid` *mismatch* between honest parties: OT-extension and other
   sub-protocols run consistency checks that abort silently when inputs differ, so two
   honest parties running with different `ssid`s will each conclude the other is malicious.
   Implementations should detect and surface `ssid` disagreement explicitly, rather than
   letting it manifest as a spurious consistency-check failure that looks indistinguishable
   from a real attack. For a worked example of the replay failure, see the
   [Zero Knowledge Proofs Not Bound to the Protocol Execution](../zk-proofs-not-bound/)
   pitfall, which covers CVE-2022-47930 (the Schnorr proof bug in `bnb-chain/tss-lib`) in
   detail.

3. **Multicast masquerading as broadcast.** A broadcast channel cannot be instantiated by
   sending the same message to each party individually. The library must enforce which message
   types are broadcast and which are point-to-point; delegating this decision to the caller
   allows a malicious party to present different views of the same round to different
   participants. Even echo-broadcast does not fully solve this: because a single echo round
   only provides local consistency, not full Byzantine agreement, a malicious sender can
   shift the split view to the second round and honest parties cannot distinguish the split
   from benign message loss.

4. **Unauthenticated or unencrypted point-to-point channels.** UC proofs of MPC protocols
   typically assume authenticated, and usually confidential, channels between every pair of
   parties. Implementations that hand-roll the transport layer (raw TCP, ad-hoc JSON over
   HTTP, or implicit trust in a central coordinator) routinely fail to realize these
   assumptions. Without per-message authentication, a network attacker can impersonate
   parties and inject messages honest parties attribute to the wrong source. Without
   confidentiality, intermediate values that the ideal functionality hides leak to the
   network. Mutual TLS between each pair of parties, keyed to the protocol's participant
   set, is typically the minimum acceptable instantiation.

### Example: Caller-Controlled Broadcast Flag (tss-lib ParseWireMessage)

**What can go wrong.** UC proofs of MPC protocols are written against idealized
communication channels, in particular a *reliable broadcast* channel in which every honest
party receives the same message from the sender in a given round. A library that cannot
tell whether a given round was supposed to be broadcast or point-to-point cannot enforce
that assumption. If the application instantiates "broadcast" as a loop of per-peer sends,
a malicious sender can equivocate (send $v_1$ to one honest party and $v_2$ to another)
and no honest participant can detect the split. Echo-broadcast, where every party
re-broadcasts what it received before accepting, provides only single-round local
consistency, not full Byzantine agreement.

**Security implication.** Honest parties end up with different views of the same protocol
round. The composition-level guarantee the UC proof relied on (that the round fixed a
single value across all honest views) no longer holds, and subsequent rounds run on
diverging state. In threshold signing the practical consequences include key-generation
concluding with honest parties disagreeing on the public key, silent denial-of-service by
a single adversary, and depending on which round is attacked, share exposure, proof
forgeries, or permanently-inconsistent key material.

**Concrete instance.** The library's sole entry-point for inbound messages delegates the
broadcast/P2P decision entirely to the application layer ([source](https://github.com/bnb-chain/tss-lib/blob/master/tss/wire.go)):

```go
// FILE: tss/wire.go — bnb-chain/tss-lib (all versions)

func ParseWireMessage(wireBytes []byte, from *PartyID, isBroadcast bool) (ParsedMessage, error) {
    wire := new(MessageWrapper)
    wire.IsBroadcast = isBroadcast  // set by caller — library never validates this
    // ...
}
```

The library never cross-checks whether the round that generated `wireBytes` is *specified*
by the protocol to be a broadcast or a P2P round. A caller that sets `isBroadcast = true`
for a P2P message, or vice versa, violates the protocol's communication model silently.

**Attack (multicast-as-broadcast split view).** Two distinct failures feed into this.
*Sender equivocation*: a malicious sender $P_m$ sends $v_1$ to one honest party and $v_2$
to another during a round whose security proof assumed reliable broadcast. If the
application instantiated "broadcast" as a loop of P2P sends, nothing catches the
inconsistency. Echo-broadcast only closes part of the gap: a single echo round gives local
consistency but not Byzantine agreement, so an adversary can shift the split into the
second round and honest parties cannot distinguish a malicious split from benign message
loss. *Classification mismatch*: because the library accepts `isBroadcast` from the caller
without validation, two honest receivers whose transport layers classify the same wire
bytes differently end up with diverging protocol state. One treats a value as globally
agreed upon while the other treats it as a personal P2P message, producing a split view
that the MPC security proof never accounts for.

[THORChain TSS](https://github.com/thorchain/tss),
[Swingby Skybridge](https://github.com/SwingbyProtocol/tss-lib), and
[Keep Network](https://github.com/keep-network/keep-core) all deployed `tss-lib` without
implementing a reliable broadcast layer, inheriting this exposure directly.

**Remediation.** The library itself has not changed this API. The correct fix at the
application layer is to enforce the broadcast flag per round using the protocol
specification as the reference, and to implement a reliable broadcast protocol (not just
echo-broadcast) for rounds that require Byzantine agreement. In settings with fewer than
$n/3$ corruptions, Bracha broadcast provides the required guarantees.

TBD: Has this really not been fixed? Are the callers of the API fixing this somehow?

### Further example: Hash-Encoding Collisions (tss-lib / IoFinnet threshlib, KS-IOF-F-02)

`bnb-chain/tss-lib` v1.3.5 and IoFinnet's `threshlib` concatenated the inputs of their
Fiat-Shamir hash with a single delimiter byte `'$'` without encoding the length of each
input. An input that happens to end in `$` (a realistic concern for variable-length
Paillier ciphertexts and serialized big integers) lets an attacker shift bytes across the
input boundary and produce a different input tuple with the same hash, so a proof honestly
computed for one statement also verifies against a crafted second one. In the `SHA512_256i`
variant used for `*big.Int` inputs, the same bug also collides `SHA512_256i(a)` with
`SHA512_256i(-a)` for any positive `a`, because Go's `big.Int.Bytes()` drops the sign. The
root cause is a hash-encoding / domain-separation failure rather than a UC composition
issue, and the same bug would break any scheme that hashes variable-length data this way.
The fix ([IoFinnet commit `369ec50`](https://github.com/IoFinnet/threshlib/commit/369ec50be1437588a9733443bcb2f15b794601d4),
imported into `bnb-chain/tss-lib` as [PR #233](https://github.com/bnb-chain/tss-lib/pull/233))
appends an 8-byte little-endian length tag after each delimiter, making the encoding
injective. See the [Hash Functions](../hash-functions/) pitfall for broader coverage of
variable-length hash-encoding issues.

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

Second, unlike the hash-collision bug shown above, which was fixed once it was publicly
disclosed (via Kudelski's KS-IOF-F-02 audit and the corresponding fix in PR #233), the
broadcast-flag issue has resisted a library-level fix by design. Enforcing broadcast
semantics inside tss-lib would require the library to ship a reliable-broadcast
implementation, which carries round-complexity and liveness costs and forces an opinion
on the application's network model. The maintainers' position has been that the transport
layer is the application's responsibility. Defensible in theory, but in practice every
major downstream deployment has shipped without a real reliable-broadcast layer, so the
bug is still openly present.

### References

- Aumasson & Shlomovits, ["Attacking Threshold Wallets"](https://eprint.iacr.org/2020/1052.pdf), ePrint 2020/1052.
- Kudelski Security, [Multiple CVEs in Threshold Cryptography Implementations](https://research.kudelskisecurity.com/2023/03/23/multiple-cves-in-threshold-cryptography-implementations/), March 2023.
