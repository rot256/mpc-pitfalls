---
title: "NEAR MPC `DomainPurpose` tagging"
category: lack-of-context-binding
subcategory: "Missing Domain Separator Across Signing Contexts"
date: 2026-02-19
primitives: [signature]
repository: https://github.com/near/mpc
issue: 2076
pr: 2163
hidden: false
---

The NEAR
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

The fix ([PR #2163](https://github.com/near/mpc/pull/2163)) introduces an explicit
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
