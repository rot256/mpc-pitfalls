---
title: "Oblivious Transfer"
class: "Oblivious Transfer"
order: 15
---

Oblivious Transfer (OT) is a two-party sub-protocol in which a sender holds two
secrets $m_0, m_1$ and a receiver holds a choice bit $b$; the receiver learns $m_b$
and nothing about $m_{1-b}$, while the sender learns nothing about $b$. OT underlies
virtually all practical MPC: it drives the offline phase of garbled circuits, provides
the correlated randomness for SPDZ-family protocols, and is the backbone of modern
2-party ECDSA protocols such as Lindell17 and DKLs23.

In practice OT is instantiated via **OT extension** (IKNP03, KOS15): a small number
of public-key "base OTs" bootstrap an unlimited number of cheap symmetric OTs.
Security of this architecture relies on an integrity check ("consistency check",
"correlation check") that the sender runs on the receiver's inputs. When the check
fails, how the implementation signals and propagates the abort decides whether the
failure is safe or catastrophic: done right, the offending party is identified and
banned; done wrong, the signal leaks a bit of the sender's base-OT secret and can be
replayed across sessions until the secret is fully recovered.

### Opaque error on OT extension consistency-check failure

**What can go wrong.** The consistency check on a malicious receiver's inputs fails
with a plain `error` return rather than a typed sentinel that the caller can branch
on. A caller that catches the error via a generic `if err != nil { return err }`
cannot distinguish a benign network timeout from a malicious consistency-check
violation, and the base-OT seed is left in memory for a retry. Trail of Bits
[summarised](https://blog.trailofbits.com/2023/09/20/dont-overextend-your-oblivious-transfer/)
the industry pattern: *"most OT extension libraries will report something along the
lines of 'correlation check failed,' which does not tell a user what to do next."*

**Security implication.** A cheating receiver manipulates its inputs so the check
fails *selectively* — causing an abort only when a specific target bit of the
sender's base-OT choice vector $\Delta$ matches a particular value. If the protocol
aborts, the receiver learns that bit; if it doesn't, the receiver learns the
complement. By repeating across many OT extension calls (each probing the next
unknown bit) the receiver recovers $\Delta$ entirely. With $\Delta$ known, the
attacker can decrypt every OT message the sender has produced or will produce —
breaking the confidentiality guarantee for every wire in every garbled circuit or MPC
computation that consumed these OTs.

**How to avoid.** Return a typed sentinel error on consistency-check failure (e.g.,
`ErrConsistencyCheckFailed`) so callers can pattern-match with `errors.Is` and enforce
the correct recovery path. Atomically zeroize the base-OT seed at the point of the
failure so no retry is possible with the same state. Treat consistency-check failures
as protocol-terminal for the current base-OT; require a fresh base-OT setup before any
further extension.

**Example: Coinbase kryptology KOS OT extension (v1.6.0).** The KOS OT extension in
`coinbase/kryptology` implements Protocol 9 of DKLs18. When the sender's consistency
check fails, `Round2Transfer` returns a plain `error` value
([source](https://github.com/coinbase/kryptology/blob/eef703320df46f97e86ead4eff178b095181b0ec/pkg/ot/extension/kos/kos.go#L269-L365)):

```go
// FILE: pkg/ot/extension/kos/kos.go — coinbase/kryptology (pre-v1.6.1)
func (sender *Sender) Round2Transfer(
    uniqueSessionId [simplest.DigestSize]byte,
    input [L][OtWidth]curves.Scalar,
    round1Output *Round1Output,
) (*Round2Output, error) {
    ...
    if subtle.ConstantTimeCompare(zPrime[:], rhs[:]) != 1 {
        // Returns an error but the caller has no structured way to know
        // the base OT state is now compromised and must be discarded.
        return nil, fmt.Errorf("cOT receiver's consistency check failed; " +
            "this may be an attempted attack; do NOT re-run the protocol")
    }
    ...
}
```

The error string warns against re-running but there is no machine-readable signal.
v1.6.1 fixed a transcription error in the consistency check itself, and the companion
v1.6.0 refactor separated OT, OT extension, and Schnorr ZKP into dedicated
session-scoped packages so a failed check now invalidates the seed object explicitly:

```go
// FILE: pkg/ot/extension/kos/kos.go — coinbase/kryptology v1.6.1 (fixed)
if subtle.ConstantTimeCompare(zPrime[:], rhs[:]) != 1 {
    sender.seed.Zeroize()                  // base OT state destroyed; no reuse possible
    return nil, ErrConsistencyCheckFailed  // typed sentinel error
}
```

Callers can now `errors.Is(err, kos.ErrConsistencyCheckFailed)` and know they must
initiate a fresh base-OT setup before any further OT extension. (Note: the kryptology
library was archived in September 2022; downstream forks that predate v1.6.1 may
still carry the uncorrected check.)

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

### Abort not propagated to parallel OT-extension instances

<div class="pitfall-flags"><span class="flag flag-tbd">TBD example</span></div>

**What can go wrong.** [DKLs23](https://eprint.iacr.org/2023/765.pdf) makes the
engineering obligation explicit: when an OT extension consistency check fails, the
implementation must abort **every** protocol instance running in parallel that
involves the same offending party. An abort that is local to a single instance —
however well-typed and however clearly identified — still leaves the other instances
running, each of which can continue leaking bits of the same base-OT state to the
same attacker.

**Security implication.** A malicious receiver opens $k$ concurrent OT extension
sessions against the same sender. The selective-abort probe in any single session
leaks one bit of $\Delta$. If the honest sender aborts only the offending session
(and not the other $k - 1$ sessions with the same peer), the attacker replays the
probe in the next session and gets the next bit. Across the $k$ sessions, the
attacker reconstructs $\Delta$ roughly $k$ times faster than with a single session —
and the per-session abort did not slow them down.

**How to avoid.** Track the offending party's identifier as part of a shared
session-state registry. When any session receives an `AbortProtocolAndBanReceiver`
(or equivalent) error naming a party, propagate that cancellation to every other
currently-running session that involves the same party. This is easier said than
done: it requires the library to have visibility into all concurrent sessions,
which in turn requires either a session manager above the OT extension API or a
convention that every session carries a cancellation token the caller can broadcast.

**Example.** *TBD.* The DKLs23 paper raises this as an engineering concern; no public
CVE is pinned to a library that aborts its local session correctly but fails the
propagation step. In practice, the panic-style and opaque-error bugs above tend to
dominate because they prevent even local identifiable abort — once those are fixed,
the cross-session propagation becomes the next layer of defence.

<!--
### Commit Timeline

| Date | Repository | Artifact | Description |
|------|-----------|----------|-------------|
| Sep 20, 2023 | — | [Trail of Bits blog](https://blog.trailofbits.com/2023/09/20/dont-overextend-your-oblivious-transfer/) | "Don't overextend your Oblivious Transfer": publicly documents selective-abort leakage in OT extension and the danger of reusing base-OT state |
| ~2022 | [coinbase/kryptology](https://github.com/coinbase/kryptology) | v1.6.0 | Fix for "Fireblocks bit probe attack" on DKLs18-based OT; refactors OT, OT extension, and Schnorr ZKP into dedicated scoped packages |
| ~2022 | [coinbase/kryptology](https://github.com/coinbase/kryptology) | v1.6.1 | Fix transcription error in DKLs18 KOS cOT extension subprotocol; incorrect consistency check corrected |
| Sep 2022 | [coinbase/kryptology](https://github.com/coinbase/kryptology) | Repository archived | Kryptology archived as read-only; no further security patches |
| Apr 10, 2024 | [silence-laboratories/dkls23](https://github.com/silence-laboratories/dkls23) | [ToB audit report](https://github.com/silence-laboratories/dkls23/blob/main/docs/ToB-SilenceLaboratories_2024.04.10.pdf) | Trail of Bits audit identifies TOB-SILA-12: OT consistency check panics instead of returning identifiable abort; 14 of 15 findings patched |

### Real-World Impact

**MetaMask Silent Shard (2024).** The Silence Laboratories DKLs23 library is the cryptographic engine behind MetaMask's Silent Shard Snap, which provides distributed-key-management (2FA-style protection) for MetaMask users. The TOB-SILA-12 finding means that any user who triggered the OT consistency-check panic — whether through network corruption or a malicious co-signer — would silently lose the ability to distinguish a legitimate abort from an attack. Given that Silent Shard is deployed in a wallet protecting production funds, the key-destruction vector was an unacceptable risk in a production setting. All 14 critical and high findings were patched before the audit report was published.

**Coinbase kryptology deprecation.** The kryptology library was archived in September 2022, shortly after shipping the v1.6.0 and v1.6.1 OT extension fixes. The archive notice means that any downstream project that forked or vendored kryptology before the v1.6.1 patch is permanently on the vulnerable version unless it manually backported the fix. Several open-source projects (e.g., [sei-protocol/coinbase-kryptology](https://github.com/sei-protocol/coinbase-kryptology)) forked the library and may carry the uncorrected consistency check depending on when they forked.
-->
