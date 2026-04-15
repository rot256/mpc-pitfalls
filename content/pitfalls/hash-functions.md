---
title: "Hash Functions"
class: "Cryptographic Primitive"
order: 9
---

- If a Merkle-Damgard construction is used (e.g. SHA2), not validating that the application is not vulnerable to extension attacks.
- When a hash function is used in multiple places in a protocol, not adding a unique constant-length domain separator.
- When a list is hashed where each element has variable length, not hashing each element independently, and then hashing the digests together.
    - Alternatively, ensure correct list hashing by prepending the length of each element.

---

# DRAFT Hash Functions

Hash functions appear in every MPC protocol — Fiat-Shamir transforms, commitment schemes, PRFs, and message authentication all rely on collision resistance, pre-image resistance, and domain separation. Three failure modes recur in implementations: using SHA-2 in a context where length-extension attacks apply; failing to separate distinct hash usages with a unique domain tag; and hashing variable-length lists without length-prefixing, enabling cross-list collisions.

### Example 1: SHA-2 Length Extension Attack

SHA-2 (SHA-256, SHA-512) uses the Merkle-Damgård construction: the hash state after processing $m$ is recoverable from $H(m)$ alone. If a protocol computes $\text{MAC} = \text{SHA256}(\text{key} \| \text{message})$ and exposes the MAC, an adversary who knows $|\text{key}|$ can compute $\text{SHA256}(\text{key} \| \text{message} \| \text{pad} \| \text{extension})$ without knowing `key`.

```go
// INSECURE: naive SHA-2 prefix MAC — vulnerable to length extension
func unsafeMAC(key, message []byte) []byte {
    h := sha256.New()
    h.Write(key)
    h.Write(message) // exposed digest leaks internal state
    return h.Sum(nil)
}
```

**Attack.** An adversary who intercepts `MAC = SHA256(secret || request_data)` forges `SHA256(secret || request_data || padding || extra_data)` without knowing `secret`, using the Merkle-Damgård state-resumption trick. In MPC, this applies to any per-round commitment scheme that concatenates a shared secret with a message and hashes directly with SHA-256.

**Remediation.** Use HMAC (double-hash prevents state extension), SHA-3 (sponge construction, inherently immune), or BLAKE2/BLAKE3:

```go
// SECURE: HMAC-SHA256 prevents length extension
func secureMAC(key, message []byte) []byte {
    mac := hmac.New(sha256.New, key)
    mac.Write(message)
    return mac.Sum(nil)
}
```

### Example 2: Missing Domain Separation — tss-lib v1.x Shared Hash Function

When a single hash function is used for multiple distinct purposes — proof challenges, commitment openings, key derivation — an adversary can present a value that is simultaneously valid in two contexts. Without a unique, constant-length domain separator for each usage, hash inputs from different protocol roles may collide.

([source](https://github.com/bnb-chain/tss-lib/blob/v1.3.5/common/hash.go))

```go
// common/hash.go — bnb-chain/tss-lib v1.3.5
// SHA512_256i is used for ALL proof challenges without domain separation:
// Schnorr proofs, MtA proofs, DLN proofs, commitment hashes — same function.
func SHA512_256i(in ...*big.Int) *big.Int {
    // no tag distinguishing which protocol context this hash is for
}
```

**Attack.** An adversary crafts a value $v$ whose serialisation is identical under two different protocol usages (possible when the delimiter-only encoding is non-injective — see KS-IOF-F-02 below). A Schnorr challenge computed for one sub-protocol satisfies the verification equation for another, allowing cross-protocol proof reuse.

**Remediation.** Prepend a unique, constant-length domain tag to every hash invocation. tss-lib v2.0.0 introduced `SHA512_256i_TAGGED`:

([source](https://github.com/bnb-chain/tss-lib/blob/v2.0.0/common/hash.go))

```go
// common/hash.go — bnb-chain/tss-lib v2.0.0
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

### Example 3: Variable-Length List Hashing Without Length Prefix (KS-IOF-F-02)

When a hash function accepts a variadic list of byte strings using a single delimiter byte between elements — but does not record the length of each element — different input tuples can produce the same concatenated byte sequence and therefore the same hash.

([source](https://github.com/bnb-chain/tss-lib/blob/v1.3.5/common/hash.go))

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

**Collision.** `SHA512_256([]byte("a$"), []byte("b"))` and `SHA512_256([]byte("a"), []byte("$b"))` both produce the byte sequence `a$$b$` and therefore the same digest. An adversary can craft two structurally different proof inputs whose byte representations collide, causing the verifier to accept a proof for the wrong statement.

**Remediation.** The IoFinnet fix ([commit `369ec50`](https://github.com/IoFinnet/threshlib/commit/369ec50be1437588a9733443bcb2f15b794601d4)) appends an 8-byte length tag after each delimiter:

([source](https://github.com/bnb-chain/tss-lib/blob/v2.0.0/common/hash.go))

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

### Commit Timeline

| Date | Repository | Artifact | Description |
|------|-----------|----------|-------------|
| ~2022 | [IoFinnet/threshlib](https://github.com/IoFinnet/threshlib) | Kudelski audit (KS-IOF-F-02) | Variable-length list hashing collision via missing per-element length tag |
| ~2022 | [IoFinnet/threshlib](https://github.com/IoFinnet/threshlib) | [commit `369ec50`](https://github.com/IoFinnet/threshlib/commit/369ec50be1437588a9733443bcb2f15b794601d4) | Fix: 8-byte length tag after each delimiter in `SHA512_256` and `SHA512_256i` |
| Aug 23, 2023 | [bnb-chain/tss-lib](https://github.com/bnb-chain/tss-lib) | [PR #233](https://github.com/bnb-chain/tss-lib/pull/233) | Import IoFinnet KS-IOF-F-02 fix into `common/hash.go` |
| Aug 26, 2023 | [bnb-chain/tss-lib](https://github.com/bnb-chain/tss-lib) | v2.0.0 | Domain-tagged `SHA512_256i_TAGGED` introduced for all proof challenge hashes |

### Real-World Impact

**BNB Chain ecosystem (2022–2023).** The KS-IOF-F-02 hash collision and missing domain separation affected all projects using `bnb-chain/tss-lib` v1.3.5 or the IoFinnet fork: SwingBy Skybridge, Keep Network, THORChain, and Multichain. The non-injective encoding was a necessary precondition for the TSSHOCK α-shuffle attack, which requires crafting two proof inputs that hash identically. The v2.0.0 release shipped both fixes simultaneously — but is not backward-compatible, so any mixed-version deployment (some parties on v1, some on v2) fails proof verification and incentivises operators to stay on the vulnerable version.
