---
title: "Hash Functions"
class: "Hash Functions"
order: 9
---

Hash functions appear everywhere in MPC protocols — Fiat-Shamir challenges, commitment
schemes, PRFs, message authentication. The three pitfalls below arise from
implementation choices that weaken a hash's implicit guarantees (collision resistance,
pre-image resistance, domain separation) in ways the surrounding protocol proof took for
granted.

### SHA-2 / Merkle-Damgård length-extension attack

**What can go wrong.** SHA-2 (SHA-256, SHA-512) uses the Merkle-Damgård construction:
the internal state after processing a message $m$ is fully recoverable from $H(m)$
alone. A protocol that builds a MAC as $H(\text{key} \,\|\, \text{message})$ and
exposes the resulting digest leaks the internal state, letting an adversary who knows
$|\text{key}|$ compute
$H(\text{key} \,\|\, \text{message} \,\|\, \text{pad} \,\|\, \text{extension})$ without
ever learning the key. The same attack applies to any construction that reveals the
output of an unkeyed Merkle-Damgård hash over a secret-prefixed input.

**Security implication.** An adversary who observes a legitimate `MAC = SHA256(key ||
request)` forges `SHA256(key || request || pad || extra)` and submits the extended
request with a valid-looking MAC. In MPC this bites any per-round commitment or
authentication scheme that concatenates a shared secret with a message and hashes
directly with SHA-256 (or SHA-512), and any Fiat-Shamir transform that hashes
`secret || transcript` rather than using a keyed construction.

**How to avoid.** Use a construction that is structurally immune to length extension:
HMAC (double-hash, specified in [RFC 2104](https://www.rfc-editor.org/rfc/rfc2104)),
SHA-3 (sponge construction), or BLAKE2/BLAKE3. Never expose `H(secret || data)`
directly as a MAC.

**Example: prefix MAC with SHA-256.** The vulnerable pattern:

```go
// INSECURE: naive SHA-2 prefix MAC — vulnerable to length extension
func unsafeMAC(key, message []byte) []byte {
    h := sha256.New()
    h.Write(key)
    h.Write(message) // exposed digest leaks internal state
    return h.Sum(nil)
}
```

An adversary who intercepts `mac = unsafeMAC(secret, request)` forges `unsafeMAC(secret,
request || padding || extra)` using the Merkle-Damgård state-resumption trick, without
knowing `secret`. The fix uses HMAC:

```go
// SECURE: HMAC-SHA256 prevents length extension
func secureMAC(key, message []byte) []byte {
    mac := hmac.New(sha256.New, key)
    mac.Write(message)
    return mac.Sum(nil)
}
```

### Missing domain separation when a hash function is reused

**What can go wrong.** When the same hash function is used for multiple distinct
purposes — Fiat-Shamir challenges for different proof types, commitment openings, key
derivation, session-ID generation — an adversary can present a single input whose hash
value is simultaneously valid in two contexts. Without a unique, constant-length domain
tag prepended to each hash invocation, inputs from different protocol roles can collide
and be interchanged.

**Security implication.** A Schnorr challenge hashed for one sub-protocol may satisfy
the verification equation for another, enabling cross-protocol proof reuse (a proof
generated under sub-protocol $A$'s statement gets accepted as a proof under
sub-protocol $B$'s statement). In threshold-signature implementations this means a ZK
proof produced in one round can be replayed as a proof in another round whose hash
happens to land on the same value. The collision probability is amplified when the
hash input encoding is itself non-injective (see next mini-pitfall).

**How to avoid.** Prepend a unique, constant-length domain-separation tag to every hash
invocation. The tag should encode the protocol name, the specific proof or purpose
inside the protocol, and typically a version number. Treat this as a required part of
any new hash usage, not an optional hardening step.

**Example: tss-lib v1.x shared `SHA512_256i`.** Before v2.0.0, `bnb-chain/tss-lib` used
a single `SHA512_256i` helper for every proof challenge — Schnorr, MtA, DLN,
commitments — with no tag distinguishing them
([source](https://github.com/bnb-chain/tss-lib/blob/v1.3.5/common/hash.go)):

```go
// common/hash.go — bnb-chain/tss-lib v1.3.5 (vulnerable)
// SHA512_256i is used for ALL proof challenges without domain separation:
// Schnorr proofs, MtA proofs, DLN proofs, commitment hashes — same function.
func SHA512_256i(in ...*big.Int) *big.Int {
    // no tag distinguishing which protocol context this hash is for
}
```

v2.0.0 introduced `SHA512_256i_TAGGED`, which prepends a per-session tag
([source](https://github.com/bnb-chain/tss-lib/blob/v2.0.0/common/hash.go)):

```go
// common/hash.go — bnb-chain/tss-lib v2.0.0 (fixed)
// SHA512_256i_TAGGED prepends a session-specific tag, providing domain
// separation between different proof types and sessions.
func SHA512_256i_TAGGED(tag []byte, in ...*big.Int) *big.Int {
    data := tag // unique per proof type and session
    for _, v := range in {
        data = append(data, v.Bytes()...)
        data = append(data, hashInputDelimiter)
        dataLen := make([]byte, 8)
        binary.LittleEndian.PutUint64(dataLen, uint64(len(v.Bytes())))
        data = append(data, dataLen...)
    }
    return new(big.Int).SetBytes(crypto.SHA512_256(data))
}
```

### Variable-length list hashed without per-element length prefix

**What can go wrong.** When a hash function accepts a variadic list of byte strings
with only a single delimiter byte between elements — and no per-element length tag —
different input tuples can serialize to the same concatenated byte sequence and
therefore produce the same hash. The encoding is not injective: two distinct inputs
map to one hash value.

**Security implication.** An adversary can craft two structurally different proof
inputs whose byte representations collide. A proof honestly computed for statement
$S_1$ produces the same challenge hash as a statement $S_2$ the adversary constructs,
so a verifier checking a proof for $S_2$ accepts the bytes of a proof for $S_1$. This
collision was a precondition for the TSSHOCK α-shuffle attack class — the attack needs
two proof inputs that hash identically to forge a range proof.

**How to avoid.** Make the encoding injective by appending a fixed-width length tag
after each element (or equivalently, length-prefixing each element before it is
serialised). An 8-byte little-endian length tag after each delimiter is enough to
disambiguate any two distinct input tuples, even when some element happens to contain
the delimiter byte.

**Example: tss-lib KS-IOF-F-02.** The vulnerable variadic hash used a single `'$'`
delimiter with no length tag
([source](https://github.com/bnb-chain/tss-lib/blob/v1.3.5/common/hash.go)):

```go
// common/hash.go — bnb-chain/tss-lib v1.3.5 (vulnerable)
const hashInputDelimiter = byte('$')

func SHA512_256(in ...[]byte) []byte {
    inLenBz := make([]byte, 8)
    binary.LittleEndian.PutUint64(inLenBz, uint64(len(in))) // counts inputs, not sizes
    data = append(data, inLenBz...)
    for _, bz := range in {
        data = append(data, bz...)
        data = append(data, hashInputDelimiter) // no length tag per element
    }
}
```

The collision: `SHA512_256([]byte("a$"), []byte("b"))` and `SHA512_256([]byte("a"),
[]byte("$b"))` both serialise to `a$$b$` and therefore produce the same digest. The
fix (IoFinnet [commit `369ec50`](https://github.com/IoFinnet/threshlib/commit/369ec50be1437588a9733443bcb2f15b794601d4),
imported into bnb-chain/tss-lib as
[PR #233](https://github.com/bnb-chain/tss-lib/pull/233)) appends an 8-byte length
tag after each delimiter
([source](https://github.com/bnb-chain/tss-lib/blob/v2.0.0/common/hash.go)):

```go
// common/hash.go — bnb-chain/tss-lib v2.0.0 (fixed)
for _, bz := range in {
    data = append(data, bz...)
    data = append(data, hashInputDelimiter)
    dataLen := make([]byte, 8)
    binary.LittleEndian.PutUint64(dataLen, uint64(len(bz)))
    data = append(data, dataLen...) // length tag makes encoding injective
}
```

<!--
### Commit Timeline

| Date | Repository | Artifact | Description |
|------|-----------|----------|-------------|
| ~2022 | [IoFinnet/threshlib](https://github.com/IoFinnet/threshlib) | Kudelski audit (KS-IOF-F-02) | Variable-length list hashing collision via missing per-element length tag |
| ~2022 | [IoFinnet/threshlib](https://github.com/IoFinnet/threshlib) | [commit `369ec50`](https://github.com/IoFinnet/threshlib/commit/369ec50be1437588a9733443bcb2f15b794601d4) | Fix: 8-byte length tag after each delimiter in `SHA512_256` and `SHA512_256i` |
| Aug 23, 2023 | [bnb-chain/tss-lib](https://github.com/bnb-chain/tss-lib) | [PR #233](https://github.com/bnb-chain/tss-lib/pull/233) | Import IoFinnet KS-IOF-F-02 fix into `common/hash.go` |
| Aug 26, 2023 | [bnb-chain/tss-lib](https://github.com/bnb-chain/tss-lib) | v2.0.0 | Domain-tagged `SHA512_256i_TAGGED` introduced for all proof challenge hashes |

### Real-World Impact

**BNB Chain ecosystem (2022–2023).** The KS-IOF-F-02 hash collision and missing domain separation affected all projects using `bnb-chain/tss-lib` v1.3.5 or the IoFinnet fork: SwingBy Skybridge, Keep Network, THORChain, and Multichain. The non-injective encoding was a necessary precondition for the TSSHOCK α-shuffle attack, which requires crafting two proof inputs that hash identically. The v2.0.0 release shipped both fixes simultaneously — but is not backward-compatible, so any mixed-version deployment (some parties on v1, some on v2) fails proof verification and incentivises operators to stay on the vulnerable version.
-->
