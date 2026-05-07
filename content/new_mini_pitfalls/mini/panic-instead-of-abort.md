---
title: "Panic or opaque error instead of structured abort"
class: "Multi-Party Accountability"
source: "oblivious-transfer.md"
---

### Panic or opaque error instead of structured abort

**What can go wrong.** The *OT (oblivious transfer) consistency check* is a verification
step in OT-extension protocols that compares the parties' transcripts of a batch of
oblivious transfers and detects when a malicious sender or receiver deviated from the
protocol. When this check fails, the failure can be reported in two equally damaging
ways:

- **Panic / abort the thread**: a Rust `panic!` (or any language's equivalent
  "crash the thread" mechanism) unwinds the stack abruptly without surfacing a
  structured error to the application layer.
- **Opaque error return**: a generic, untyped error value indistinguishable from
  benign failures (network timeout, decode error). A caller that catches it via a
  generic `if err != nil { return err }` cannot tell that a malicious peer just
  probed the protocol.

At minimum, both failures prevent graceful recovery of the broader system. For
protocols that further require *identifiable abort* (such as
[DKLs23](https://eprint.iacr.org/2023/765)), they also discard the information about
*which* peer triggered the failure, leaving honest parties unable to ban the
cheater specifically without collateral damage.

**Security implication.** The application is left with two bad choices, both of
which an adversary can turn into attacks:

- **Key destruction**: treat the panic as evidence that some party cheated and
  destroy the key share. An adversary who can trigger the panic at will now has a
  *griefing* primitive that lets them destroy honest parties' keys without needing
  to know any key material.
- **Retry without exclusion**: treat the panic as a transient error and retry
  without banning the offending party. The offending party repeats the selective-abort
  probe across multiple retries, accumulating bits of the base-OT state.

**How to avoid.** Replace every adversary-reachable abort path (assertions, panics,
generic errors) with a structured, terminal error — a typed sentinel the caller
can pattern-match on (e.g., `errors.Is(err, ErrConsistencyCheckFailed)` in Go, a
typed `Result::Err` variant in Rust). Treat the failure as protocol-terminal:
zeroize any compromised key material (e.g., the base-OT seed) at the failure
point so no retry with the same state is possible. Where the protocol requires
*identifiable abort*, the error must additionally carry the offending party's
identifier so the caller can ban that party specifically and continue with the
remaining honest peers.

**Example: Silence Laboratories dkls23 (TOB-SILA-12).** Trail of Bits' [February 2024 review](https://github.com/trailofbits/publications/blob/master/reviews/2024-02-silencelaboratories-silentshard-securityreview.pdf) of Silence Laboratories' DKLs23 library identified TOB-SILA-12, a high-severity finding titled *"Implementation mishandles selective abort attacks"*. The pairwise multiplication (MtA) layer called the underlying COTe (correlated oblivious transfer with errors) sender via `.expect(...)`, which panics on `Err` without surfacing which party caused the failure. The audit reproduces the offending lines (citing `dkls23/src/sign/pairwise_mta.rs` lines 278–282 in the pre-fix codebase):

```rust
// dkls23/src/sign/pairwise_mta.rs — silence-laboratories/dkls23 (vulnerable, pre-fix)
let (cot_sender_shares, round2_output) = self
    .state
    .cot_sender
    .process((&round1_output, &alice_input))
    .expect("error while processing soft_spoken ot message round 1");
// ↑ panic on COTe Err; no party ID propagates to the caller
```

The audit's *Exploit Scenario* section for TOB-SILA-12 spells out the selective-abort-accumulation attack: a malicious receiver causes the sender to panic on each session, the caller cannot identify which peer to exclude and continues new sessions with the same attacker, and over many sessions the receiver "recovers the base OT choices of the other participants" and uses them to "(retroactively) recover the input of these other participants in another signing session, one of which corresponds to their private key share" (audit, p. 42).

The fix is two-layer: the SoftSpokenOT primitive returns a structured `AbortProtocolAndBanReceiver` error when the consistency check fails; the DSG (signing) layer catches that error and re-emits it as `AbortProtocolAndBanParty(party_idx)` with the specific peer's identity attached so the library caller can denylist them:

```rust
// SoftSpokenOT layer — returns AbortProtocolAndBanReceiver on consistency-check failure
//   (sl-crypto/crates/sl-oblivious/src/soft_spoken/...)
//
// DSG (signing) layer — propagates with the party identifier:
.map_err(|_| SignError::AbortProtocolAndBanParty(party_idx as u8))?;
```

The two-layer separation is a useful lesson: the OT primitive identifies that the receiver cheated, while the higher protocol layer attaches which peer that receiver was, so the library user can abort all concurrent sessions with that peer and refuse future participation.
