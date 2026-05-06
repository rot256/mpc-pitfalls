---
title: "Panic instead of identifiable abort"
class: "Multi-Party Accountability"
source: "oblivious-transfer.md"
---

### Panic instead of identifiable abort

**What can go wrong.** When the OT consistency check fails, a Rust `panic!` (or any
language's equivalent "crash the thread" mechanism) unwinds the stack without
carrying any information about *which* peer triggered the failure. The application
layer sees an opaque runtime error, not a structured abort message naming the
offending party. The specification of modern threshold protocols like DKLs23 is
explicit that the abort must identify the cheater so honest parties can ban them
without collateral damage; a bare panic offers none of this information.

**Security implication.** The application is left with two bad choices, both of
which an adversary can turn into attacks:

- **Key destruction**: treat the panic as evidence that some party cheated and
  destroy the key share. An adversary who can trigger the panic at will now has a
  *griefing* primitive that lets them destroy honest parties' keys without needing
  to know any key material.
- **Retry without exclusion**: treat the panic as a transient error and retry
  without banning the offending party. The offending party repeats the selective-abort
  probe across multiple retries, accumulating bits of the base-OT state exactly as
  in the opaque-error case above.

**How to avoid.** Replace every abort path (assertions, panics, generic errors) in
the OT extension consistency check with a structured error type that carries the
offending party's identifier. The caller can then ban that party specifically and
continue the protocol with the remaining honest peers. This is the "identifiable
abort" requirement that DKLs23 and similar protocols make explicit.

**Example: Silence Laboratories dkls23 (TOB-SILA-12).** The DKLs23 implementation
used by MetaMask's Silent Shard Snap panicked on OT-consistency-check failure
([source](https://github.com/silence-laboratories/dkls23/blob/main/src/proto/signing.rs)):

```rust
// FILE: src/proto/signing.rs — silence-laboratories/dkls23 (vulnerable, pre-audit)
// OT consistency check failure: panics instead of returning an identifiable error.
// The caller cannot determine which party cheated, preventing proper banning.
assert!(ot_check_passed, "OT consistency check failed");
// ↑ panic unwinds the stack; no party ID is propagated to the caller
```

Trail of Bits identified this as TOB-SILA-12 in their April 2024 audit. The fix
replaces the `panic!` with a typed error carrying the offending party's identifier:

```rust
// FILE: src/proto/signing.rs — silence-laboratories/dkls23 (fixed)
if !ot_check_passed {
    // Return a typed error containing the party ID so the caller can:
    //   1. Ban the specific party
    //   2. Abort all parallel sessions with that party
    return Err(ProtocolError::AbortProtocolAndBanReceiver {
        party_id: offending_party,
    });
}
```
