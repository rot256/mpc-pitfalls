---
title: "UC Protocols"
class: "Protocol"
order: 5
---

- Point-to-Point Channels lack Encryption and Authentication.
    - Implementers often hand-roll P2P communication implementations. These hand-rolled implementations often do not have all the desired cryptographic properties that are needed for secure MPC.
- Sessions IDs and sub-session IDs are not used for each message to prevent mix-and-match attacks.
    - Disagreement on session IDs should be detected as soon as possible. If two parties run an OT extension protocol using different session IDs, they might consider each other malicious when the consistency check fails.
- Using Multicast Rather than Broadcast i.e. a broadcast channel cannot be instantiated by simply sending the message to all parties.
    - Even an Echo Broadcast does not provide all desirable properties of a reliable broadcast (as it cannot provide full Byzantine consensus). As an example, the [Forget-and-Forgive attack](https://eprint.iacr.org/2020/1052.pdf) is not prevented by an Echo Broadcast, as the attacker can just move the attack to the second round of the broadcast.

### Example

Binance tss-lib's [`ParseWireMessage`](https://github.com/bnb-chain/tss-lib/blob/c84c096da546e9ce9742f9f9cb9e7f06fedc9268/tss/wire.go#L16-L25) accepts an `isBroadcast` flag set entirely by the caller, with no enforcement by the library:

```go
// tss/wire.go — bnb-chain/tss-lib
func ParseWireMessage(wireBytes []byte, from *PartyID, isBroadcast bool) (ParsedMessage, error) {
    wire := new(MessageWrapper)
    wire.IsBroadcast = isBroadcast  // Caller decides — no enforcement
    // ...
}
```

Downstream projects (THORChain, Swingby, Keep Network) deployed tss-lib without implementing reliable broadcast, inheriting the vulnerability directly.

- **Missing session IDs (tss-lib v1.x):** The `ssid` parameter specified in CGGMP21 was never used. The v2.0.0 release notes explicitly list "Add session information for sub protocols to prevent message replay" -- confirming the prior omission. ioFinnet threslib similarly overlooked session IDs (per Arcadia Group analysis).
- **Cascading failures (Multichain fastMPC):** Missing session IDs combined with reduced DLN proof iterations (1 instead of the specified 128) enabled the Verichains TSSHOCK c-guess attack -- full key extraction from a single signing ceremony. Multichain was later compromised with over $130M in stolen funds.

### References

- Aumasson & Shlomovits, ["Attacking Threshold Wallets"](https://eprint.iacr.org/2020/1052.pdf), ePrint 2020/1052.
- Verichains, [TSSHOCK](https://blog.verichains.io/p/tsshock-critical-vulnerabilities), BlackHat USA 2023.
- Arcadia Group, [TSS security analysis](https://blog.arcadia.agency/unveiling-the-secrets-of-binances-tss-adoption-vulnerabilities-and-security-analysis-4c2fd2bf2d9a).

---

# DRAFT UC Protocols

The **Universal Composability (UC)** framework [Can01] gives the strongest security guarantee
available for MPC protocols: a UC-secure protocol behaves like an incorruptible ideal
functionality regardless of what else runs concurrently alongside it. But UC security is not
a property of the cryptographic core alone — it extends to the communication infrastructure.
A protocol proven UC-secure under ideal channels provides *no security guarantee* when those
channels are replaced by unauthenticated sockets, unenforced broadcast flags, or
session-unbound proofs. Three categories of implementation failure recur across real
deployments:

1. **Ambiguous hash encoding.** When the domain-separation hash used for Fiat-Shamir
   challenges does not encode input lengths, two structurally different inputs can produce
   the same hash value. An adversary can exploit this to substitute a proof generated for
   one session or statement into a different one.

2. **Missing session identifiers.** CGGMP21 and other modern threshold ECDSA protocols
   mandate that every sub-protocol ZK proof include a session sub-ID (`ssid`) in its
   Fiat-Shamir hash. Without it, a valid proof from session $A$ is indistinguishable from a
   valid proof for session $B$, enabling cross-session replay attacks.

3. **Multicast masquerading as broadcast.** A broadcast channel cannot be instantiated by
   sending the same message to each party individually. The library must enforce which message
   types are broadcast and which are point-to-point; delegating this decision to the caller
   allows a malicious party to present different views of the same round to different
   participants. Even echo-broadcast does not fully solve this: the
   [Forget-and-Forgive attack](https://eprint.iacr.org/2020/1052.pdf) can shift the attack
   to the second round of the broadcast.

### Example 1: Hash Collision via Missing Per-Input Length Prefix — tss-lib / IoFinnet threshlib (KS-IOF-F-02)

All Fiat-Shamir challenges and commitment hashes in `bnb-chain/tss-lib` pass through a
central `SHA512_256` helper. In versions up to v1.3.5, this function separated its
variable-number inputs with a single delimiter byte `'$'` but did not record the *length*
of each input ([source](https://github.com/bnb-chain/tss-lib/blob/v1.3.5/common/hash.go)):

```go
// FILE: common/hash.go — bnb-chain/tss-lib v1.3.5 (vulnerable)

const hashInputDelimiter = byte('$')

func SHA512_256(in ...[]byte) []byte {
    inLenBz := make([]byte, 8)
    binary.LittleEndian.PutUint64(inLenBz, uint64(len(in))) // counts inputs but not their sizes
    data = append(data, inLenBz...)
    for _, bz := range in {
        data = append(data, bz...)
        data = append(data, hashInputDelimiter) // single byte separator, no length prefix
    }
    // ...
}
```

**Attack.** When an input byte sequence ends with the delimiter `'$'`, the concatenation
is ambiguous: `SHA512_256([]byte("a$"), []byte("b"))` and
`SHA512_256([]byte("a"), []byte("$b"))` produce the same byte string and therefore the same
hash. A malicious party can craft two proof instances — one for statement $S_1$ and one for
statement $S_2$ — whose Fiat-Shamir inputs are permutations of the same raw bytes. The proof
for $S_1$ then satisfies the verification equation for $S_2$, allowing the adversary to
answer challenges it never computed honestly. In the `SHA512_256i` variant (used for
`*big.Int` inputs), the same collision is possible whenever a serialized big integer ends
with the delimiter; additionally, `SHA512_256i(-a)` produces the same bytes as
`SHA512_256i(a)` for any positive `a`, so negated witnesses pass the challenge check.

**Remediation.** Kudelski Security's audit of IoFinnet's fork (`threshlib`) identified this
as finding **KS-IOF-F-02**. The fix
([IoFinnet commit `369ec50`](https://github.com/IoFinnet/threshlib/commit/369ec50be1437588a9733443bcb2f15b794601d4))
appends an 8-byte little-endian length tag after each delimiter, making the encoding
injective. `bnb-chain/tss-lib` imported the same fix in
[PR #233](https://github.com/bnb-chain/tss-lib/pull/233) ([source](https://github.com/bnb-chain/tss-lib/blob/v2.0.0/common/hash.go)):

```go
// FILE: common/hash.go — bnb-chain/tss-lib v2.0.0 (fixed)

for _, bz := range in {
    data = append(data, bz...)
    data = append(data, hashInputDelimiter)
    dataLen := make([]byte, 8)
    binary.LittleEndian.PutUint64(dataLen, uint64(len(bz)))
    data = append(data, dataLen...) // length of each buffer enforces proper domain separation
}
```

### Example 2: Missing Session ID in ZK Proof Hashes — tss-lib v1.x (CGGMP21 §4)

The [CGGMP21](https://eprint.iacr.org/2021/060) protocol specification requires that every
sub-protocol proof — RangeProof (MtA), FacProof, ModProof, SchnorrProof — bind its
Fiat-Shamir challenge to a **session sub-ID** (`ssid`). The `ssid` is derived from the
public parameters of the current protocol session and ensures that a proof computed in one
session cannot be replayed in another.

In `bnb-chain/tss-lib` v1.x, none of these proof types included an `ssid`. A representative
example is the Schnorr proof used during keygen ([source](https://github.com/bnb-chain/tss-lib/blob/v1.3.5/crypto/schnorr/schnorr.go)):

```go
// FILE: crypto/schnorr/schnorr.go — bnb-chain/tss-lib v1.3.5 (vulnerable)

func NewZKProof(x *big.Int, X *crypto.ECPoint) (*ZKProof, error) {
    a := new(big.Int).SetBytes(common.GetRandomPositiveInt(q).Bytes())
    alpha := crypto.ScalarBaseMult(EC(), a)
    // Challenge binds only to the commitment and public key — no session ID
    e := common.SHA512_256i(alpha.X(), alpha.Y(), X.X(), X.Y())
    // ...
}
```

**Attack.** Party $P_i$ generates a valid Schnorr proof $\pi_i$ during key-generation
session $A$. Later, in signing session $B$, a colluding party replays $\pi_i$ as its own
round-2 contribution. Because the proof hash does not include the session identifier, every
honest party's verification passes. If $P_i$ is able to substitute its keygen proof into
a signing round, it avoids computing an honest partial signature, breaking the protocol's
output correctness guarantee. The same vector applies to range proofs (MtA) and modulus
proofs: a range proof from an old signing session is structurally valid in a new one.

**Remediation.** [PR #256](https://github.com/bnb-chain/tss-lib/pull/256) (commit
[`1ddfc956`](https://github.com/bnb-chain/tss-lib/commit/1ddfc956), merged August 23,
2023) added a `sessionId []byte` parameter to all affected proof types and prepended it to
every Fiat-Shamir hash ([source](https://github.com/bnb-chain/tss-lib/blob/v2.0.0/crypto/schnorr/schnorr.go)):

```go
// FILE: crypto/schnorr/schnorr.go — bnb-chain/tss-lib v2.0.0 (fixed)

func NewZKProof(sessionId []byte, x *big.Int, X *crypto.ECPoint) (*ZKProof, error) {
    // ...
    // Challenge now includes the session ID — proof is bound to this session only
    e := common.SHA512_256i(append(sessionId, alpha.X(), alpha.Y(), X.X(), X.Y())...)
    // ...
}
```

The v2.0.0 release notes confirm: *"Add session information for sub protocols to prevent
message replay."* The fix is not backward-compatible: parties running v1.x and v2.0.0
cannot interoperate because their proof challenges diverge at the session-ID step.

### Example 3: Caller-Controlled Broadcast Flag — tss-lib ParseWireMessage

The library's sole entry-point for inbound messages delegates the broadcast/P2P decision
entirely to the application layer ([source](https://github.com/bnb-chain/tss-lib/blob/master/tss/wire.go)):

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

**Attack (Aumasson & Shlomovits "Forget-and-Forgive").** In echo-broadcast, each party
re-broadcasts what it received before accepting. A malicious party $P_m$ sends different
messages $v_1, v_2, \ldots$ to different honest parties during round 1, then during round 2
("forgive") claims it sent a *consistent* message and challenges the parties to prove
otherwise. Since echo-broadcast only provides consistency within a single echo round, not
full Byzantine agreement, honest parties cannot distinguish between a malicious split and a
benign message loss. By setting `isBroadcast` incorrectly at the transport layer, $P_m$
can cause some honest parties to treat a value as globally agreed upon while others treat it
as a personal P2P message, creating a split view of the protocol state that the MPC
security proof never accounts for.

Downstream projects — [THORChain TSS](https://github.com/thorchain/tss),
[Swingby Skybridge](https://github.com/SwingbyProtocol/tss-lib), and
[Keep Network](https://github.com/keep-network/keep-core) — all deployed `tss-lib` without
implementing a reliable broadcast layer, inheriting this exposure directly.

**Remediation.** The library itself has not changed this API. The correct fix at the
application layer is to enforce the broadcast flag per round using the protocol
specification as the reference, and to implement a reliable broadcast protocol (not just
echo-broadcast) for rounds that require Byzantine agreement. In settings with fewer than
$n/3$ corruptions, Bracha broadcast provides the required guarantees.

### Commit Timeline

| Date | Repository | Artifact | Description |
|------|-----------|----------|-------------|
| ~2022 | [IoFinnet/threshlib](https://github.com/IoFinnet/threshlib) | Kudelski Security audit (KS-IOF-F-02) | Hash collision in `SHA512_256`: missing per-input length prefix allows two different input tuples to produce the same hash |
| ~2022 | [IoFinnet/threshlib](https://github.com/IoFinnet/threshlib) | [commit `369ec50`](https://github.com/IoFinnet/threshlib/commit/369ec50be1437588a9733443bcb2f15b794601d4) | Fix KS-IOF-F-02: add 8-byte length tag after each delimiter in `SHA512_256` and `SHA512_256i` |
| Mar 28, 2023 | [thorchain/thornode](https://gitlab.com/thorchain/thornode) | — | THORChain halts network ($180M TVL) after Verichains delivers TSSHOCK PoC; tss-lib session-ID absence identified as contributing factor |
| Jul 7, 2023 | Multichain | — | Multichain fastMPC compromised; $130M+ in cross-chain bridge funds drained; missing session IDs + reduced DLN iterations enabled TSSHOCK c-guess attack |
| Aug 23, 2023 | [bnb-chain/tss-lib](https://github.com/bnb-chain/tss-lib) | [PR #233](https://github.com/bnb-chain/tss-lib/pull/233) | Fix hash collision: import IoFinnet KS-IOF-F-02 fix into `common/hash.go` |
| Aug 23, 2023 | [bnb-chain/tss-lib](https://github.com/bnb-chain/tss-lib) | [PR #256](https://github.com/bnb-chain/tss-lib/pull/256) / [commit `1ddfc956`](https://github.com/bnb-chain/tss-lib/commit/1ddfc956) | Fix missing session IDs: add `sessionId` parameter to all ZK proof types (RangeProof, FacProof, ModProof, SchnorrProof) |
| Aug 26, 2023 | [bnb-chain/tss-lib](https://github.com/bnb-chain/tss-lib) | v2.0.0 release | Both fixes shipped; **not backward-compatible** with v1.3.5; downstream projects must upgrade all parties simultaneously |

### Real-World Impact

**Multichain fastMPC (\$130M, July 2023).**
Multichain's cross-chain bridge used a
custom fork of GG20 called fastMPC. Verichains found two compounding defects: session IDs
were absent from all sub-protocol proofs, and the DLN proof iteration count was reduced from
the specified 128 to 1, dramatically weakening the discrete-log soundness guarantee. The
combination enabled the TSSHOCK c-guess attack — an adversary who can probe the DLN proof
oracle just once can extract a signing key share in a single ceremony. In July 2023,
Multichain's bridge was drained of over \$130M across multiple chains. While the full cause
is disputed (private key custody issues were also reported), Verichains confirmed that the
cryptographic weaknesses were present and exploitable.

**THORChain ($180M TVL, March 2023).** After Verichains privately shared a TSSHOCK proof
of concept with affected projects, THORChain halted its entire mainnet to assess exposure.
THORChain's TSS implementation is a direct downstream of `bnb-chain/tss-lib` and was
running v1.x at the time — without session IDs in any ZK proof. The halt lasted long enough
to affect live liquidity positions; THORChain ultimately patched by upgrading its tss-lib
dependency and implementing the v2.0.0 session-byte requirement.

**Binance ecosystem downstream exposure (pre-August 2023).** The `bnb-chain/tss-lib`
library is the reference implementation for BNB Chain's threshold custody infrastructure
and has been forked by dozens of projects including SwingBy Skybridge, Keep Network,
and ioFinnet. All forks running v1.3.5 or earlier were missing both the hash-collision fix
and the session-ID binding. Because v2.0.0 is not backward-compatible, any deployment that
upgraded only some of its signing parties remained in a mixed state where the session-ID
mismatch caused proof verification failures — incentivizing operators to skip the upgrade
or revert, leaving the vulnerability in place.
