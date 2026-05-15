---
title: "Missing Domain Separator Across Signing Contexts"
class: lack-of-context-binding
source: "signatures.md"
primitives: [signature]
---

### Missing Domain Separator Across Signing Contexts

**What can go wrong.** When the same signing key is used in multiple protocol roles,
signing round-1 commitments vs round-2 packages in a DKG, authenticating API requests
vs producing blockchain transactions, or tagging message types in a single protocol,
each role must bind its messages to a unique domain-separation tag.
If the tag is missing or identical across roles, a
signature produced for one role is structurally valid for the other: the
same bytes verify against the same key in both contexts. The tag can live at the
signing primitive itself (a context string mixed into the hash, such as
[RFC 8032](https://datatracker.ietf.org/doc/html/rfc8032)'s `Ed25519ctx`) or at the
protocol layer (a per-method or per-key purpose marker that gates which API
entry-point a key can serve).

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

**Example: NEAR MPC `DomainPurpose` tagging**
([issue #2076](https://github.com/near/mpc/issues/2076),
[PR #2163](https://github.com/near/mpc/pull/2163)). The NEAR
MPC node exposes a threshold key to three different methods on the contract: `sign()`
for arbitrary user-supplied payloads, `verify_foreign_transaction()` for foreign-chain
(Bitcoin, Ethereum) transaction attestation used by bridges, and
`request_app_private_key()` for confidential key derivation (CKD). All three call paths
can route to the same set of distributed keys. Before the fix, the contract enforced
only that the *curve* matched the call: any Secp256k1 key could back either `sign()` or
`verify_foreign_transaction()`. A caller could therefore submit a foreign-chain
transaction payload to the generic `sign()` method, collect a threshold signature, and
then replay it to a bridge calling `verify_foreign_transaction()` against the same key;
the bridge would accept the signature as proof that the foreign transaction had been
attested.

The fix ([PR #2163](https://github.com/near/mpc/pull/2163), merged February 19, 2026) introduces an explicit
per-domain `DomainPurpose` enum:

```rust
// FILE: crates/contract-interface/src/types/state.rs — near/mpc (after PR #2163)
pub enum DomainPurpose {
    /// Domain is used by `sign()`.
    Sign,
    /// Domain is used by `verify_foreign_transaction()`.
    ForeignTx,
    /// Domain is used by `request_app_private_key()` (Confidential Key Derivation).
    CKD,
}

pub struct DomainConfig {
    pub id: DomainId,
    pub scheme: SignatureScheme,
    pub purpose: Option<DomainPurpose>, // new: purpose tag per domain
}
```

Each contract entry-point now requires the target domain to carry the matching purpose
(`crates/contract/src/lib.rs`):

```rust
// FILE: crates/contract/src/lib.rs — near/mpc (after PR #2163)

// in sign(...)
if domain_config.purpose != DomainPurpose::Sign {
    env::panic_str(
        &InvalidParameters::WrongDomainPurpose { /* ... */ }
            .message("sign() may only target domains with purpose Sign")
            .to_string(),
    );
}

// in verify_foreign_transaction(...)
if domain_config.purpose != DomainPurpose::ForeignTx {
    env::panic_str(
        &InvalidParameters::WrongDomainPurpose { /* ... */ }
            .message("verify_foreign_transaction() requires a domain with purpose ForeignTx")
            .to_string(),
    );
}

// in request_app_private_key(...)
if domain_config.purpose != DomainPurpose::CKD {
    env::panic_str(
        &InvalidParameters::WrongDomainPurpose { /* ... */ }
            .message("request_app_private_key() may only target domains with purpose CKD")
            .to_string(),
    );
}
```
