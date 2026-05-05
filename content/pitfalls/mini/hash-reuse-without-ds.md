---
title: "Missing domain separation when a hash function is reused"
class: "Others"
source: "hash-functions.md"
---

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
