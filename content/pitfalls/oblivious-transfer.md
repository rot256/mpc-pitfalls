---
title: "Oblivious Transfer"
class: "Cryptographic Primitive"
order: 15
---

- Many oblivious transfer extension protocols rely on consistency checks to get active security. However, they suffer from selective abort attacks, where succeeding or failing a consistency check leaks a few bits of information on the underlying OT secret. As a result, reusing the base OT secrets for multiple OT extension protocols is dangerous.
    - [DKLs23](https://eprint.iacr.org/2023/765.pdf) states that an abort during OT extension requires the involved party to abort all instances of the protocol running in parallel that involve the offending party. This is extremely difficult to guarantee from an engineering standpoint.

### Example

The KOS OT extension in Coinbase kryptology returns a generic `error` on consistency-check failure, with no signal that base OT state must be invalidated ([source](https://github.com/coinbase/kryptology/blob/eef703320df46f97e86ead4eff178b095181b0ec/pkg/ot/extension/kos/kos.go#L269-L365)):

```go
// pkg/ot/extension/kos/kos.go — Coinbase kryptology
func (sender *Sender) Round2Transfer(
    uniqueSessionId [simplest.DigestSize]byte,
    input [L][OtWidth]curves.Scalar,
    round1Output *Round1Output,
) (*Round2Output, error)
```

A caller receiving this error has no way to distinguish a benign network failure from a malicious consistency-check violation. If the caller retries with the same base OTs, each attempt leaks bits of the base OT secret via selective abort.

- In Silence Laboratories' dkls23 implementation (used by MetaMask), the OT extension consistency check panicked on failure instead of returning a structured error identifying the offending party (TOB-SILA-12). Without identifiable abort, the application cannot determine which party cheated; if it blames everyone and destroys the key, that enables a key destruction attack; if it blames no one and allows retry, that enables key extraction.
- Trail of Bits observed this pattern systematically: "most OT extension libraries will report something along the lines of 'correlation check failed,' which does not tell a user what to do next."

### References

- Trail of Bits, [Don't overextend your Oblivious Transfer](https://blog.trailofbits.com/2023/09/20/dont-overextend-your-oblivious-transfer/), September 2023.
- Trail of Bits, [audit of Silence Laboratories](https://github.com/nicedayzhu/silence-laboratories-multiparty-sig/blob/main/docs/Trail_of_Bits_Silence_Laboratories_Multi-Party_Threshold_Signature_Scheme_Security_Assessment.pdf) (TOB-SILA-12), April 2024.
- [DKLs23](https://eprint.iacr.org/2023/765.pdf).
