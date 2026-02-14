---
title: "Hash functions"
class: "Cryptographic Primitive"
order: 9
---

- If a Merkle-Damgard construction is used (e.g. SHA2), not validating that the application is not vulnerable to extension attacks.
- When a hash function is used in multiple places in a protocol, not adding a unique constant-length domain separator.
- When a list is hashed where each element has variable length, not hashing each element independently, and then hashing the digests together.
    - Alternatively, ensure correct list hashing by prepending the length of each element.
