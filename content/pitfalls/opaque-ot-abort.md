---
title: "Opaque Error on OT Extension Consistency-Check Failure"
class: failure-recovery-and-abort-handling
hidden: false
source: "oblivious-transfer.md"
primitives: [oblivious-transfer]
---

### Opaque Error on OT Extension Consistency-Check Failure

<div class="pitfall-flags"><span class="flag flag-related">Soft-merged with <a href="#panic-or-opaque-error-instead-of-structured-abort">Panic or Opaque Error Instead of Structured Abort</a></span></div>

**What can go wrong.** OT-extension protocols include a *consistency check* by which
the sender verifies that the receiver constructed its transfer queries honestly; a
failed check indicates a malicious receiver. In a vulnerable implementation, this
check returns a plain `error` rather than a typed sentinel that the caller can branch
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
