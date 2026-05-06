---
title: "SHA-2 / Merkle-Damgård length-extension attack"
class: "Others"
source: "hash-functions.md"
---

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
