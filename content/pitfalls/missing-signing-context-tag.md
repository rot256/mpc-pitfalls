---
title: "Missing Domain Separator Across Signing Contexts"
class: lack-of-context-binding
hidden: false
order: 3
source: "signatures.md"
primitives: [signature]
---


**What can go wrong.** When the same signing key is used in multiple protocol roles, signing round-1 commitments vs round-2 packages in a DKG, authenticating API requests vs producing blockchain transactions, or tagging message types in a single protocol, each role must bind its messages to a unique domain-separation tag. If the tag is missing or identical across roles, a signature produced for one role is valid for the other: the same bytes verify against the same key in both contexts. The tag can live at the signing primitive itself (a context string mixed into the hash, such as [RFC 8032](https://datatracker.ietf.org/doc/html/rfc8032)'s `Ed25519ctx`) or at the protocol layer (a per-method or per-key purpose marker that gates which API entry-point a key can serve).

**Security implication.** A malicious party who obtains a signature in role $A$
presents the same bytes as if they had been produced for role $B$. In an MPC threshold
network that exposes both a generic `sign()` method and a specialized
`verify_foreign_transaction()` method against the same distributed key, a bridge that
calls `verify_foreign_transaction()` to confirm that a foreign-chain transaction was
attested by the threshold network can be defeated by a caller who submits the same
payload to `sign()` instead: the MPC network produces a valid threshold signature
(since `sign()` is willing to sign arbitrary bytes), and the attacker replays the
resulting signature into the bridge as evidence of a verified foreign transaction. The
bridge has no way to tell the two apart, both signatures verify under the same
threshold public key over the same bytes.

**How to avoid.** Bind every signature to its protocol role. Two complementary points
of enforcement:

- *Primitive-level domain separation.* Prepend a unique, version-bearing tag to the
  message before signing. For Ed25519, use
  [RFC 8032](https://datatracker.ietf.org/doc/html/rfc8032)'s `Ed25519ctx` with a
  non-empty context per role; for Schnorr or generic hash-then-sign, hash
  `tag || message` rather than `message` alone. Rotate tags when the protocol version
  changes so old-version signatures do not retroactively validate under a new role.
- *Protocol-level domain separation.* Tag each distributed key with the purpose it is
  allowed to serve, and reject at the API entry-point any request that targets a key
  whose purpose does not match the call.
